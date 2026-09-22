'use strict';

const StorageService = require('./StorageService');
const { PUBLIC_API_URL } = require('../config/env');

const TELEGRAM_TEXT_LIMIT = 3800;
const BARK_TITLE_BYTES = 120;
const BARK_BODY_BYTES = 2400;
const REQUEST_TIMEOUT_MS = 5000;
const SCAN_INTERVAL_MS = 30_000;

const kindLabels = Object.freeze({
  deny_5m: '拒绝访客集中出现',
  suspicious_10m: '疑似机器人集中出现',
  challenge_fail: '静默验证失败率过高',
  token_replay: '读取凭证疑似重放',
  cross_site: '同类风险跨站扩散',
  inventory_stale: '导航站运行清单已过期',
  protocol_mismatch: '导航站维护协议不兼容',
  site_update: '导航站实际组件有新版待评估'
});

function truncateUnicode(value, maxCharacters) {
  const chars = [...String(value || '')];
  if (chars.length <= maxCharacters) return chars.join('');
  return `${chars.slice(0, Math.max(0, maxCharacters - 13)).join('')}…请进入后台查看`;
}

function truncateUtf8(value, maxBytes) {
  const input = String(value || '');
  if (Buffer.byteLength(input, 'utf8') <= maxBytes) return input;
  const suffix = '…请进入后台查看';
  const budget = Math.max(0, maxBytes - Buffer.byteLength(suffix, 'utf8'));
  let output = '';
  for (const char of input) {
    if (Buffer.byteLength(output + char, 'utf8') > budget) break;
    output += char;
  }
  return output + suffix;
}

function createRateQueue(intervalMs, sender) {
  let chain = Promise.resolve();
  let lastStartedAt = 0;
  return payload => {
    const run = async () => {
      const wait = Math.max(0, lastStartedAt + intervalMs - Date.now());
      if (wait) await new Promise(resolve => setTimeout(resolve, wait));
      lastStartedAt = Date.now();
      return sender(payload);
    };
    const result = chain.then(run, run);
    chain = result.catch(() => undefined);
    return result;
  };
}

function describeAlert(item) {
  const details = item.details || {};
  if (item.recovered) return `风险恢复：${kindLabels[item.kind] || item.kind}\n范围：${details.siteName || item.siteKey || '所有站点'}\n连续 ${details.window || '观察窗口'} 未再次达到阈值。`;
  const lines = [
    `${item.severity === 'critical' ? '紧急' : '高风险'}：${kindLabels[item.kind] || item.kind}`,
    `站点：${item.siteName || details.siteName || item.siteKey || '所有站点'}`,
    `窗口：${details.window || '实时聚合'}`
  ];
  if (details.visitors != null) lines.push(`唯一访客：${details.visitors}`);
  if (details.events != null) lines.push(`事件数：${details.events}`);
  if (details.failed != null) lines.push(`验证失败：${details.failed}/${details.total}（${Math.round((details.ratio || 0) * 100)}%）`);
  if (details.signal) lines.push(`风险信号：${details.signal}`);
  if (details.sites != null) lines.push(`影响站点：${details.sites}`);
  if (details.reportedAt !== undefined) lines.push(`最后上报：${details.reportedAt || '从未上报'}`);
  if (details.protocolVersion) lines.push(`当前协议：${details.protocolVersion}；期望：${details.expectedProtocol}`);
  if (details.updates != null) lines.push(`待评估组件：${details.updates} 个`);
  if (details.versions) lines.push(`版本差异：${details.versions}`);
  lines.push(`管理后台：${PUBLIC_API_URL}/admin`);
  return lines.join('\n');
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
  });
  const text = await response.text();
  if (!response.ok) throw Object.assign(new Error(`HTTP ${response.status}: ${text.slice(0, 180)}`), { statusCode: response.status });
  return response.status;
}

async function sendTelegram(settings, message) {
  if (!settings.telegramToken || !settings.telegramChatId) throw new Error('Telegram Bot Token 或 Chat ID 未配置');
  const text = truncateUnicode(message, TELEGRAM_TEXT_LIMIT);
  const statusCode = await postJson(
    `https://api.telegram.org/bot${encodeURIComponent(settings.telegramToken)}/sendMessage`,
    { chat_id: settings.telegramChatId, text, disable_web_page_preview: true }
  );
  return { statusCode, payloadSize: [...text].length };
}

async function sendBark(settings, title, message) {
  if (!settings.barkDeviceKey) throw new Error('Bark Device Key 未配置');
  if (!/^https:\/\//i.test(settings.barkServerUrl || '')) throw new Error('Bark 服务地址必须使用 HTTPS');
  const safeTitle = truncateUtf8(title, BARK_TITLE_BYTES);
  const body = truncateUtf8(message, BARK_BODY_BYTES);
  const statusCode = await postJson(`${settings.barkServerUrl.replace(/\/$/, '')}/push`, {
    device_key: settings.barkDeviceKey,
    title: safeTitle,
    body,
    group: truncateUtf8(settings.barkGroup || '风险中心', 80),
    url: `${PUBLIC_API_URL}/admin`
  });
  return { statusCode, payloadSize: Buffer.byteLength(body, 'utf8') };
}

let telegramQueue = createRateQueue(1200, payload => sendTelegram(payload.settings, payload.message));
let barkQueue = createRateQueue(2000, payload => sendBark(payload.settings, payload.title, payload.message));
let timer = null;
let running = false;
let lastHourlyDigestAt = Date.now();
let lastDailyDigestAt = Date.now();

function rebuildQueues(settings) {
  telegramQueue = createRateQueue(Math.max(1000, settings.telegramIntervalMs || 1200), payload => sendTelegram(payload.settings, payload.message));
  barkQueue = createRateQueue(Math.max(1000, settings.barkIntervalMs || 2000), payload => sendBark(payload.settings, payload.title, payload.message));
}

async function deliver(item, settings, { testProvider = '' } = {}) {
  const message = item.message || describeAlert(item);
  const title = item.title || (item.recovered ? '风险中心恢复通知' : `风险中心${item.severity === 'critical' ? '紧急' : '风险'}告警`);
  const providers = testProvider ? [testProvider] : [
    ...(settings.telegramEnabled ? ['telegram'] : []),
    ...(settings.barkEnabled ? ['bark'] : [])
  ];
  const results = [];
  for (const provider of providers) {
    try {
      const outcome = provider === 'telegram'
        ? await telegramQueue({ settings, message })
        : await barkQueue({ settings, title, message });
      const result = { alertKey: item.key, provider, success: true, ...outcome };
      await StorageService.recordAlertDelivery(result); results.push(result);
    } catch (error) {
      const result = { alertKey: item.key, provider, success: false, statusCode: error.statusCode, error: error.message };
      await StorageService.recordAlertDelivery(result); results.push(result);
    }
  }
  return results;
}

async function sendDigest(settings, period) {
  const activity = await StorageService.listAlertActivity(100);
  const active = activity.active.filter(item => item.active);
  const failed = activity.deliveries.filter(item => !item.success && new Date(item.createdAt) >= new Date(Date.now() - (period === '1小时' ? 3600000 : 86400000)));
  const item = {
    key: `digest:${period}:${Date.now()}`,
    kind: `${period}风险摘要`, severity: 'high', siteName: '所有站点',
    details: { window: period, visitors: active.length, events: failed.length }
  };
  return deliver(item, settings);
}

async function scan() {
  if (running) return;
  running = true;
  try {
    const settings = await StorageService.getAlertSettings({ includeSecrets: true });
    if (!settings?.enabled) return;
    rebuildQueues(settings);
    const candidates = await StorageService.listAlertCandidates(settings);
    const claimed = await StorageService.claimAlertNotifications(candidates, settings.cooldownMinutes);
    for (const item of claimed) await deliver(item, settings);
    const recovered = await StorageService.resolveRecoveredAlerts(settings.cooldownMinutes);
    for (const item of recovered) await deliver(item, settings);
    const now = Date.now();
    if (settings.hourlyDigestEnabled && now - lastHourlyDigestAt >= 3600000) {
      lastHourlyDigestAt = now; await sendDigest(settings, '1小时');
    }
    if (settings.dailyDigestEnabled && now - lastDailyDigestAt >= 86400000) {
      lastDailyDigestAt = now; await sendDigest(settings, '24小时');
    }
  } catch (error) {
    console.error('风险告警扫描失败：', error?.stack || error);
  } finally { running = false; }
}

function start() {
  if (timer) return;
  timer = setInterval(() => { void scan(); }, SCAN_INTERVAL_MS);
  timer.unref?.();
}

function stop() {
  if (timer) clearInterval(timer);
  timer = null;
}

async function test(provider) {
  const settings = await StorageService.getAlertSettings({ includeSecrets: true });
  if (!settings) throw new Error('告警配置尚未初始化');
  rebuildQueues(settings);
  const results = await deliver({
    key: `test:${provider}:${Date.now()}`, kind: '测试告警', severity: 'high', siteName: '风险中心',
    details: { window: '人工测试', visitors: 1, events: 1 }
  }, settings, { testProvider: provider });
  if (!results[0]?.success) throw new Error(results[0]?.error || '测试推送失败');
  return results[0];
}

async function notifyUpstreamUpdates(projects) {
  const settings = await StorageService.getAlertSettings({ includeSecrets: true });
  if (!settings?.enabled || !settings.upstreamUpdateAlertEnabled || (!settings.telegramEnabled && !settings.barkEnabled)) return false;
  rebuildQueues(settings);
  const lines = ['检测到上游项目发布新版本：'];
  for (const item of projects) {
    lines.push(`${item.name}：${item.latestVersion || '版本未知'}（${item.integrationMode === 'direct' ? '直接集成' : item.integrationMode === 'signal_source' ? '信号来源' : '参考项目'}）`);
  }
  lines.push('系统不会自动升级生产环境，请进入后台评估后再决定是否跟进。', `管理后台：${PUBLIC_API_URL}/admin`);
  const results = await deliver({
    key: `upstream:${projects.map(item => `${item.projectKey}@${item.latestVersion}`).join(',')}`,
    title: '风险中心上游更新提醒',
    message: lines.join('\n'),
    severity: 'high'
  }, settings);
  return results.some(item => item.success);
}

module.exports = {
  start, stop, scan, test, deliver, notifyUpstreamUpdates,
  truncateUnicode, truncateUtf8, createRateQueue, describeAlert,
  TELEGRAM_TEXT_LIMIT, BARK_TITLE_BYTES, BARK_BODY_BYTES
};
