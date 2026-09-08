'use strict';

// 业务日界、Node 定时器及本地格式化统一使用北京时间；数据库时间仍以 UTC 保存。
process.env.TZ = 'Asia/Shanghai';

const app = require('./src/app');
const { PORT } = require('./src/config/env');
const { closeDatabase } = require('./src/config/database');
const { dbWriteCoordinator } = require('./src/services/DbWriteCoordinator');
const { initializeDatabase } = require('./src/models/SystemModel');
const { initializeSourceTokenTables, ensureAllPartnersHaveSid } = require('./src/models/SourceTokenModel');
const { initializeAdsTable } = require('./src/models/AdsModel');
const { initializeMirrorsTable, syncMirrorsToPartners } = require('./src/models/MirrorModel');
const { startJobs, stopJobs } = require('./src/jobs/cron');

let httpServer;
let shuttingDown = false;
let shutdownExitCode = 0;

const FATAL_SHUTDOWN_SIGNALS = new Set(['UNCAUGHT_EXCEPTION', 'UNHANDLED_REJECTION']);

process.on('uncaughtException', error => {
  console.error('未捕获异常（uncaughtException）：', error?.stack || error);
  void shutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', reason => {
  console.error('未处理的 Promise 拒绝（unhandledRejection）：', reason?.stack || reason);
  void shutdown('UNHANDLED_REJECTION');
});

initializeDatabase()
  .then(initializeSourceTokenTables)
  .then(initializeAdsTable)
  .then(initializeMirrorsTable)
  .then(syncMirrorsToPartners)
  .then(ensureAllPartnersHaveSid)
  .then(() => {
    httpServer = app.listen(PORT, () => {
      console.log(`互助友链系统已启动：http://localhost:${PORT}`);
      startJobs();
    });
  })
  .catch(error => {
    console.error('系统初始化失败：', error);
    process.exit(1);
  });

async function shutdown(signal) {
  if (FATAL_SHUTDOWN_SIGNALS.has(signal)) shutdownExitCode = 1;
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`收到 ${signal}，正在停止服务…`);

  try {
    let serverClosePromise = Promise.resolve();
    if (httpServer) {
      // 调用 close 后立即停止接收新连接；现有连接与后台任务并行排空。
      serverClosePromise = new Promise((resolve, reject) => {
        httpServer.close(error => {
          if (error) reject(error);
          else resolve();
        });
      });
    }

    // 同时等待 HTTP 连接与后台任务排空；Promise.all 会立即订阅两侧拒绝，
    // 避免 close 回调较早报错时形成短暂的 unhandledRejection。
    const [jobsResult] = await Promise.all([
      stopJobs({ drainTimeoutMs: 15000 }),
      serverClosePromise
    ]);
    if (!jobsResult.drained) {
      console.warn(`服务停机时仍有 ${jobsResult.pending} 个后台任务未在限时内完成。`);
    }
    // 所有 HTTP 连接已关闭、未来任务已取消调度后，才拒绝新的写入并排空当前事务。
    dbWriteCoordinator.beginShutdown();
    const writeQueueResult = await dbWriteCoordinator.drain({ timeoutMs: 15000 });
    if (!writeQueueResult.drained) {
      console.warn(`服务停机时仍有 ${writeQueueResult.pending} 个 SQLite 写入未在限时内完成。`);
    }
    await closeDatabase();
    process.exit(shutdownExitCode);
  } catch (error) {
    console.error(`服务关闭失败（${signal}）：`, error?.stack || error);
    process.exit(1);
  }
}

process.once('SIGINT', () => { void shutdown('SIGINT'); });
process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
