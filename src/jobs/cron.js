'use strict';

const cron = require('node-cron');
const LogModel = require('../models/LogModel');
const SystemModel = require('../models/SystemModel');
const InspectionService = require('../services/InspectionService');
const PingService = require('../services/PingService');
const CacheService = require('../services/CacheService');
const { sendAdminAlert } = require('../services/AlertService');

let started = false;
let backlinkTask = null;
let databaseMaintenanceTask = null;
let deepRevivalTask = null;
const intervals = [];
const runningJobs = new Set();
let stopping = false;

/**
 * 统一追踪后台任务，保证定时器回调不会产生未处理拒绝，且停机时可以排空。
 */
function runTrackedJob(label, worker) {
  if (!started || stopping) return null;

  let trackedPromise;
  trackedPromise = Promise.resolve()
    .then(worker)
    .catch(error => {
      console.error(`${label}失败：`, error?.stack || error?.message || error);
      return { error };
    })
    .finally(() => runningJobs.delete(trackedPromise));

  runningJobs.add(trackedPromise);
  return trackedPromise;
}

function reportCleanupFailures(results) {
  results.forEach(result => {
    if (result.status === 'rejected') {
      console.error(`清理 ${result.table} 过期流水失败：`, result.reason?.message || result.reason);
    }
  });
}

/** 集中启动反链巡检、合作站 Ping 探活和日志清理任务。镜像延迟改由访客浏览器实时测量。 */
function startJobs() {
  if (started) return;
  started = true;
  stopping = false;

  backlinkTask = cron.schedule('0 3 * * *', () => {
    runTrackedJob('定时反向友链巡检', () => InspectionService.checkAllBacklinks({
      sendAdminAlert,
      onDataChanged: CacheService.clearPublicCache
    }));
  }, { timezone: 'Asia/Shanghai' });

  databaseMaintenanceTask = cron.schedule('30 3 * * *', () => {
    runTrackedJob('SQLite 无感维护任务', async () => {
      const result = await SystemModel.runDatabaseMaintenance();
      const checkpoint = result?.checkpoint || {};
      if (Number(checkpoint.busy || 0) > 0) {
        console.warn('SQLite WAL 截断遇到活跃读写，本轮已安全跳过部分页。');
      }
    });
  }, { timezone: 'Asia/Shanghai' });

  deepRevivalTask = cron.schedule('0 4 * * *', () => {
    runTrackedJob('死站深度复活任务', async () => {
      const sharedOptions = { onDataChanged: CacheService.clearPublicCache };
      try {
        await PingService.runDeepPingRevival(sharedOptions);
      } catch (error) {
        console.error('死站 Ping 深度复活任务失败：', error.message);
      }

      try {
        await InspectionService.checkDeepDeadBacklinks({
          ...sharedOptions,
          sendAdminAlert
        });
      } catch (error) {
        console.error('死站反链深度复活任务失败：', error.message);
      }
    });
  }, { timezone: 'Asia/Shanghai' });

  const cleanupTimer = setInterval(() => {
    runTrackedJob('定时清理过期流水', async () => {
      reportCleanupFailures(await LogModel.cleanupOldLogs());
    });
  }, 60 * 60 * 1000);
  cleanupTimer.unref();
  intervals.push(cleanupTimer);

  const pingTimer = setInterval(() => {
    runTrackedJob('定时站点探活', () => PingService.runFullPingInspection({
      onDataChanged: CacheService.clearPublicCache
    }));
  }, 2 * 60 * 60 * 1000);
  pingTimer.unref();
  intervals.push(pingTimer);

}

async function stopCronTask(task) {
  if (!task) return;
  await task.stop();
  await task.destroy();
}

/**
 * 停止未来调度，并等待已经启动的任务完成。超过 drainTimeoutMs 后返回，
 * 避免极端网络假死阻止进程永久退出。
 */
async function stopJobs({ drainTimeoutMs = 15000 } = {}) {
  stopping = true;

  const cronTasks = [backlinkTask, databaseMaintenanceTask, deepRevivalTask].filter(Boolean);
  backlinkTask = null;
  databaseMaintenanceTask = null;
  deepRevivalTask = null;

  while (intervals.length) clearInterval(intervals.pop());

  const stopResults = await Promise.allSettled(cronTasks.map(stopCronTask));
  stopResults.forEach(result => {
    if (result.status === 'rejected') {
      console.error('停止定时调度器失败：', result.reason?.stack || result.reason);
    }
  });

  started = false;

  const pendingJobs = Array.from(runningJobs);
  if (pendingJobs.length === 0) return { drained: true, pending: 0 };

  const timeoutMs = Math.max(1, Number(drainTimeoutMs) || 15000);
  let timeoutId;
  const drainResult = await Promise.race([
    Promise.allSettled(pendingJobs).then(() => ({ drained: true })),
    new Promise(resolve => {
      timeoutId = setTimeout(() => resolve({ drained: false }), timeoutMs);
    })
  ]);
  clearTimeout(timeoutId);

  const pending = runningJobs.size;
  if (!drainResult.drained) {
    console.warn(`后台任务排空等待超过 ${timeoutMs}ms，仍有 ${pending} 个任务未结束。`);
  }
  return { drained: drainResult.drained, pending };
}

module.exports = { startJobs, stopJobs, runTrackedJob };
