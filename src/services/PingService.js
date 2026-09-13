'use strict';

const axios = require('axios');
const PartnerModel = require('../models/PartnerModel');
const MirrorModel = require('../models/MirrorModel');
const { assertSafeBacklinkUrl, createPinnedAxiosConfig } = require('./InspectionService');
const { runPromisePool } = require('../utils/asyncPool');
const { sendPingInspectionSummary } = require('./InspectionAlertService');

let pingInspectionInProgress = false;
let mirrorCheckInProgress = false;
const HEALTHY_PING_REFRESH_MS = 12 * 60 * 60 * 1000;

function notifyChanged(options) {
  if (typeof options?.onDataChanged === 'function') options.onDataChanged();
}

function notifyProgress(options, progress) {
  if (typeof options?.onProgress !== 'function') return;
  try { options.onProgress(progress); } catch (error) { console.error('更新站点探活进度失败：', error?.message || error); }
}

function classifyPingResult(item = {}) {
  if (item.task_error || item.skipped) return 'task_error';
  if (item.alert_event === 'ping_recovered') return 'recovered';
  if (item.alert_event === 'ping_first_failure') return 'first_failure';
  if (item.alert_event === 'ping_offline') return 'reached_dead';
  if (Number(item.ping_failed_count || 0) > 0 || item.ping_status === 'unreachable') return 'ongoing_failure';
  if (item.ping_status === 'ok' && !item.error) return 'normal';
  return 'task_error';
}

function buildPingReport({ mode = 'scheduled', targets = [], results = [], scope = {} } = {}) {
  const counts = { normal: 0, first_failure: 0, ongoing_failure: 0, reached_dead: 0, recovered: 0, task_errors: 0 };
  for (const item of results) {
    const category = classifyPingResult(item);
    if (category === 'task_error') counts.task_errors += 1;
    else counts[category] += 1;
  }
  return {
    started: true,
    mode,
    target_total: targets.length,
    external_target_total: Number(scope.external_target_total ?? targets.length),
    internal_skipped: Number(scope.internal_skipped || 0),
    ping_exempt_skipped: Number(scope.ping_exempt_skipped || 0),
    completed: results.length,
    ...counts,
    state_change_count: results.filter(item => Boolean(item?.alert_event)).length,
    results
  };
}

function describePingResult(item = {}) {
  if (item.skipped) return item.reason || '连通性免检，未执行探活';
  if (item.alert_event === 'ping_recovered') return '本轮恢复，已重新展示';
  if (item.alert_event === 'ping_first_failure') return '首次异常，继续展示并等待下一轮复检';
  if (item.alert_event === 'ping_offline') return '达到三次失败，已标记失效并从前台隐藏';
  if (Number(item.ping_failed_count || 0) > 0 || item.ping_status === 'unreachable') return '持续异常，等待后续复检';
  if (item.ping_status === 'ok' && !item.error) return '连通正常，无需处理';
  return item.error || '探活任务执行异常';
}

function enrichPingResult(link, result = {}) {
  const enriched = {
    name: link.name,
    domain: link.domain,
    url: link.url,
    contact: link.contact,
    backlink_url: link.backlink_url,
    checked_at: new Date().toISOString(),
    ...result
  };
  if (!enriched.result_text) enriched.result_text = describePingResult(enriched);
  return enriched;
}

function throwIfAborted(signal) {
  if (!signal?.aborted) return;
  const error = signal.reason instanceof Error ? signal.reason : new Error('探活任务已取消');
  if (!error.code) error.code = 'TASK_ABORTED';
  throw error;
}

/** Axios 收到 asyncPool 的 controller.abort() 后会转成 ERR_CANCELED / CanceledError。 */
function isTaskTimeoutAbort(error, signal) {
  const reason = signal?.reason;
  return error?.code === 'TASK_TIMEOUT'
    || reason?.code === 'TASK_TIMEOUT'
    || ((error?.name === 'AbortError' || error?.name === 'CanceledError' || error?.code === 'ERR_CANCELED')
      && reason?.code === 'TASK_TIMEOUT');
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
  const { signal } = options;
  let targetUrl = String(url);
  for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
    throwIfAborted(signal);
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
      signal,
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
  const timedOut = isTaskTimeoutAbort(error, options.signal);
  // 停机取消不落库；任务超时必须记录失败，以推进 1/3、2/3、3/3 状态机。
  if (options.signal?.aborted && !timedOut) throwIfAborted(options.signal);
  const failedCount = Number(link.ping_failed_count || 0) + 1;
  const status = failedCount >= 3 ? 'unreachable' : (link.ping_status || 'ok');
  const failureReason = timedOut ? '连接超时（任务超过 15 秒）' : String(error?.message || '探活失败');
  await PartnerModel.recordPingFailure(link.id, failedCount, status, {
    signal: options.signal,
    // 超时是本轮巡检的最终业务结论，必须允许写入；停机取消会在上方直接抛出。
    allowAbortedWrite: timedOut
  });
  notifyChanged(options);
  return {
    id: link.id,
    ping_status: status,
    ping_failed_count: failedCount,
    previous_failed_count: Number(link.ping_failed_count || 0),
    alert_event: failedCount === 1 ? 'ping_first_failure' : failedCount === 3 ? 'ping_offline' : null,
    failure_reason: failureReason,
    last_ping_at: new Date().toISOString(),
    error: failureReason
  };
}

/** 单站状态机：连续三次失败下架，后续任一次成功立即复活。 */
async function pingSingleLink(link, options = {}) {
  throwIfAborted(options.signal);
  if (Number(link.ping_exempt) === 1) {
    return {
      id: link.id,
      ping_exempt: 1,
      ping_status: 'ok',
      ping_failed_count: 0,
      last_ping_at: link.last_ping_at || null,
      skipped: true,
      reason: '连通性免检'
    };
  }
  let success = false;
  let lastError = null;
  try {
    const head = await requestSafePing(link.url, 'HEAD', { signal: options.signal });
    success = head.status >= 200 && head.status < 400;
  } catch (error) {
    const timedOut = isTaskTimeoutAbort(error, options.signal);
    if (options.signal?.aborted && !timedOut) throwIfAborted(options.signal);
    lastError = error;
    const headStatus = Number(error.response?.status || 0);
    if (!timedOut && [403, 405, 501].includes(headStatus)) {
      try {
        const getResponse = await requestSafePing(link.url, 'GET', { signal: options.signal });
        success = getResponse.status >= 200 && getResponse.status < 400;
      } catch (fallbackError) {
        const fallbackTimedOut = isTaskTimeoutAbort(fallbackError, options.signal);
        if (options.signal?.aborted && !fallbackTimedOut) throwIfAborted(options.signal);
        lastError = fallbackError;
      }
    }
  }

  if (success) {
    throwIfAborted(options.signal);
    if (link.ping_status === 'ok' && Number(link.ping_failed_count) === 0) {
      if (!pingTimestampIsFresh(link.last_ping_at)) {
        await PartnerModel.touchPingTimestamp(link.id, { signal: options.signal });
        notifyChanged(options);
        return {
          id: link.id,
          ping_status: 'ok',
          ping_failed_count: 0,
          alert_event: null,
          last_ping_at: new Date().toISOString(),
          revived: false,
          timestamp_refreshed: true
        };
      }
      return {
        id: link.id,
        ping_status: 'ok',
        ping_failed_count: 0,
        alert_event: null,
        last_ping_at: link.last_ping_at || null,
        revived: false,
        timestamp_refreshed: false
      };
    }

    const revived = link.ping_status === 'unreachable';
    const recovered = revived || Number(link.ping_failed_count || 0) > 0;
    await PartnerModel.recordPingSuccess(link.id, { signal: options.signal });
    notifyChanged(options);
    return {
      id: link.id,
      ping_status: 'ok',
      ping_failed_count: 0,
      previous_failed_count: Number(link.ping_failed_count || 0),
      alert_event: recovered ? 'ping_recovered' : null,
      last_ping_at: new Date().toISOString(),
      revived
    };
  }
  return persistPingFailure(link, lastError, options);
}

async function inspectPingTargets(links, options = {}) {
  const concurrency = Math.max(1, Number(options.concurrency) || 3);
  const taskTimeoutMs = Math.max(1, Number(options.taskTimeoutMs) || 15000);
  const completedResults = [];
  const publish = (link, value) => {
    const result = enrichPingResult(link, value);
    completedResults.push(result);
    const progress = buildPingReport({ mode: options.mode, targets: links, results: completedResults });
    notifyProgress(options, {
      targetTotal: progress.target_total,
      completed: progress.completed,
      normal: progress.normal,
      abnormal: progress.first_failure + progress.ongoing_failure + progress.reached_dead + progress.task_errors,
      recovered: progress.recovered
    });
    return result;
  };
  const settled = await runPromisePool(links, concurrency, async (link, _index, signal) => {
    const taskOptions = { ...options, signal };
    try {
      return publish(link, await pingSingleLink(link, taskOptions));
    } catch (error) {
      const timedOut = isTaskTimeoutAbort(error, signal);
      if (signal?.aborted && !timedOut) throwIfAborted(signal);
      try {
        return publish(link, await persistPingFailure(link, error, taskOptions));
      } catch (persistError) {
        return publish(link, {
          id: link.id,
          ping_status: link.ping_status || 'ok',
          task_error: true,
          error: String(persistError.message || '探活结果持久化失败')
        });
      }
    }
  }, taskTimeoutMs);

  return settled.map((result, index) => result.status === 'fulfilled'
    ? result.value
    : enrichPingResult(links[index], {
        id: links[index].id,
        ping_status: links[index].ping_status || 'ok',
        task_error: true,
        error: String(result.reason?.message || result.reason || '探活任务异常')
      }));
}

/** 动态三并发常规探活；高频失败超过 30 次的长期死站由每日深度任务接管。 */
async function runFullPingInspection(options = {}) {
  if (pingInspectionInProgress) return { started: false, reason: '连通性探活正在执行' };
  pingInspectionInProgress = true;
  try {
    const mode = options.mode === 'manual' ? 'manual' : 'scheduled';
    const taskOptions = {
      alwaysSendSummary: mode === 'manual',
      includeAllResultsInSummary: mode === 'manual',
      ...options,
      mode
    };
    const [links, scope] = await Promise.all([
      mode === 'manual' ? PartnerModel.listManualPingTargets() : PartnerModel.listPingTargets(),
      PartnerModel.getPingInspectionScope(mode)
    ]);
    const results = await inspectPingTargets(links, taskOptions);
    const report = buildPingReport({ mode, targets: links, results, scope });
    const shouldSendSummary = taskOptions.aggregateAlerts
      && (taskOptions.alwaysSendSummary === true || report.state_change_count > 0);
    if (shouldSendSummary) {
      report.alert_summary = await sendPingInspectionSummary(
        report,
        taskOptions.sendAdminAlert,
        taskOptions.alertTaskLabel || (mode === 'manual' ? '后台手动链群健康体检' : '站点连通性探活'),
        { includeAllResults: taskOptions.includeAllResultsInSummary === true }
      );
    }
    return report;
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
    const taskOptions = { ...options, mode: 'deep_revival' };
    const results = await inspectPingTargets(links, taskOptions);
    const report = buildPingReport({ mode: 'deep_revival', targets: links, results });
    if (taskOptions.aggregateAlerts && report.state_change_count > 0) {
      report.alert_summary = await sendPingInspectionSummary(
        report,
        taskOptions.sendAdminAlert,
        taskOptions.alertTaskLabel || '死站 Ping 深度复活',
        { includeAllResults: false }
      );
    }
    return report;
  } finally {
    pingInspectionInProgress = false;
  }
}

async function checkMirrorHealth(mirror, options = {}) {
  const startedAt = Date.now();
  try {
    // 统一经过 SSRF 校验、DNS 固定与逐跳重定向复检，禁止 Axios 再次解析原域名。
    const response = await requestSafePing(mirror.url, 'GET', { timeoutMs: 4000, signal: options.signal });
    if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
    const pingMs = Math.max(1, Date.now() - startedAt);
    // 节点启停由后台管理员管理；真实测速在访客浏览器完成，不能用一次后端探测覆写 status。
    return { id: mirror.url, status: 'online', last_ping_ms: pingMs };
  } catch (error) {
    throwIfAborted(options.signal);
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
      (mirror, _index, signal) => checkMirrorHealth(mirror, { signal }),
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
  buildPingReport,
  isPingInspectionInProgress: () => pingInspectionInProgress,
  checkAllMirrors
};
