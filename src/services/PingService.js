'use strict';

const axios = require('axios');
const PartnerModel = require('../models/PartnerModel');
const MirrorModel = require('../models/MirrorModel');
const { assertSafeBacklinkUrl, createPinnedAxiosConfig } = require('./InspectionService');
const { runPromisePool } = require('../utils/asyncPool');

let pingInspectionInProgress = false;
let mirrorCheckInProgress = false;
const HEALTHY_PING_REFRESH_MS = 12 * 60 * 60 * 1000;

function notifyChanged(options) {
  if (typeof options?.onDataChanged === 'function') options.onDataChanged();
}

function pingTimestampIsFresh(value, now = Date.now()) {
  if (!value) return false;
  const normalized = String(value).includes('T') ? String(value) : String(value).replace(' ', 'T');
  const timestamp = Date.parse(normalized);
  if (!Number.isFinite(timestamp)) return false;
  return Math.max(0, now - timestamp) < HEALTHY_PING_REFRESH_MS;
}

/** HEAD/GET 轻量探活；每次重定向都重新执行 SSRF 与 DNS 固定校验。 */
async function requestSafePing(url, method, options = {}) {
  const timeoutMs = Math.max(1, Number(options.timeoutMs) || 5000);
  let targetUrl = String(url);
  for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
    const safeTarget = await assertSafeBacklinkUrl(targetUrl);
    const pinned = createPinnedAxiosConfig(safeTarget, {
      'User-Agent': 'Mozilla/5.0 (compatible; XinghuanPingBot/1.0)',
      Accept: '*/*'
    });
    const response = await axios.request({
      ...pinned,
      method,
      timeout: timeoutMs,
      maxRedirects: 0,
      maxContentLength: 5 * 1024 * 1024,
      maxBodyLength: 5 * 1024 * 1024,
      validateStatus: status => status >= 200 && status < 400
    });
    if ([301, 302, 303, 307, 308].includes(response.status) && response.headers.location) {
      if (redirectCount === 5) throw new Error('探活地址重定向次数超过限制');
      targetUrl = new URL(response.headers.location, safeTarget.url).href;
      continue;
    }
    return response;
  }
  throw new Error('探活地址重定向失败');
}

async function persistPingFailure(link, error, options = {}) {
  const failedCount = Number(link.ping_failed_count || 0) + 1;
  const status = failedCount >= 3 ? 'unreachable' : (link.ping_status || 'ok');
  await PartnerModel.recordPingFailure(link.id, failedCount, status);
  notifyChanged(options);
  return {
    id: link.id,
    ping_status: status,
    ping_failed_count: failedCount,
    last_ping_at: new Date().toISOString(),
    error: String(error?.message || '探活失败')
  };
}

/** 单站状态机：连续三次失败下架，后续任一次成功立即复活。 */
async function pingSingleLink(link, options = {}) {
  let success = false;
  let lastError = null;
  try {
    const head = await requestSafePing(link.url, 'HEAD');
    success = head.status >= 200 && head.status < 400;
  } catch (error) {
    lastError = error;
    const headStatus = Number(error.response?.status || 0);
    if ([403, 405, 501].includes(headStatus)) {
      try {
        const getResponse = await requestSafePing(link.url, 'GET');
        success = getResponse.status >= 200 && getResponse.status < 400;
      } catch (fallbackError) {
        lastError = fallbackError;
      }
    }
  }

  if (success) {
    if (link.ping_status === 'ok' && Number(link.ping_failed_count) === 0) {
      if (!pingTimestampIsFresh(link.last_ping_at)) {
        await PartnerModel.touchPingTimestamp(link.id);
        notifyChanged(options);
        return {
          id: link.id,
          ping_status: 'ok',
          ping_failed_count: 0,
          last_ping_at: new Date().toISOString(),
          revived: false,
          timestamp_refreshed: true
        };
      }
      return {
        id: link.id,
        ping_status: 'ok',
        ping_failed_count: 0,
        last_ping_at: link.last_ping_at || null,
        revived: false,
        timestamp_refreshed: false
      };
    }

    const revived = link.ping_status === 'unreachable';
    await PartnerModel.recordPingSuccess(link.id);
    notifyChanged(options);
    return {
      id: link.id,
      ping_status: 'ok',
      ping_failed_count: 0,
      last_ping_at: new Date().toISOString(),
      revived
    };
  }
  return persistPingFailure(link, lastError, options);
}

async function inspectPingTargets(links, options = {}) {
  const concurrency = Math.max(1, Number(options.concurrency) || 3);
  const taskTimeoutMs = Math.max(1, Number(options.taskTimeoutMs) || 15000);
  const settled = await runPromisePool(links, concurrency, async link => {
    try {
      return await pingSingleLink(link, options);
    } catch (error) {
      try {
        return await persistPingFailure(link, error, options);
      } catch (persistError) {
        return {
          id: link.id,
          ping_status: link.ping_status || 'ok',
          error: String(persistError.message || '探活结果持久化失败')
        };
      }
    }
  }, taskTimeoutMs);

  return settled.map((result, index) => result.status === 'fulfilled'
    ? result.value
    : {
        id: links[index].id,
        ping_status: links[index].ping_status || 'ok',
        error: String(result.reason?.message || result.reason || '探活任务异常')
      });
}

/** 动态三并发常规探活；高频失败超过 30 次的长期死站由每日深度任务接管。 */
async function runFullPingInspection(options = {}) {
  if (pingInspectionInProgress) return { started: false, reason: '连通性探活正在执行' };
  pingInspectionInProgress = true;
  try {
    const links = await PartnerModel.listPingTargets();
    const results = await inspectPingTargets(links, options);
    return { started: true, total: links.length, results };
  } finally {
    pingInspectionInProgress = false;
  }
}

/** 每日低频检测被常规任务退避的长期死站，为恢复上线提供机会。 */
async function runDeepPingRevival(options = {}) {
  if (pingInspectionInProgress) return { started: false, reason: '连通性探活正在执行' };
  pingInspectionInProgress = true;
  try {
    const links = await PartnerModel.listDeepPingRevivalTargets();
    const results = await inspectPingTargets(links, options);
    return { started: true, total: links.length, results };
  } finally {
    pingInspectionInProgress = false;
  }
}

async function checkMirrorHealth(mirror) {
  const startedAt = Date.now();
  try {
    // 统一经过 SSRF 校验、DNS 固定与逐跳重定向复检，禁止 Axios 再次解析原域名。
    const response = await requestSafePing(mirror.url, 'GET', { timeoutMs: 4000 });
    if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
    const pingMs = Math.max(1, Date.now() - startedAt);
    // 节点启停由后台管理员管理；真实测速在访客浏览器完成，不能用一次后端探测覆写 status。
    return { id: mirror.url, status: 'online', last_ping_ms: pingMs };
  } catch (error) {
    return { id: mirror.url, status: 'offline', error: error.message };
  }
}

/** 动态并发探测镜像节点；全局只允许一轮运行，同时最多三个外发请求。 */
async function checkAllMirrors(options = {}) {
  if (mirrorCheckInProgress) {
    console.warn('镜像探活任务仍在运行，本轮已跳过。');
    return [];
  }

  mirrorCheckInProgress = true;
  try {
    const mirrors = await MirrorModel.getEnabledMirrors();
    const concurrency = Math.max(1, Number(options.concurrency) || 3);
    const taskTimeoutMs = Math.max(1, Number(options.taskTimeoutMs) || 15000);
    const settled = await runPromisePool(
      mirrors,
      concurrency,
      mirror => checkMirrorHealth(mirror),
      taskTimeoutMs
    );

    return settled.map((result, index) => {
      if (result.status === 'fulfilled') return result.value;
      const mirror = mirrors[index];
      const message = result.reason?.message || String(result.reason || '未知错误');
      console.error(`镜像节点 ${mirror.url} 探活任务异常：`, message);
      return { id: mirror.url, status: 'error', error: message };
    });
  } finally {
    mirrorCheckInProgress = false;
  }
}

module.exports = {
  requestSafePing,
  pingSingleLink,
  runFullPingInspection,
  runDeepPingRevival,
  checkAllMirrors
};
