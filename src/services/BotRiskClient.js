'use strict';

const crypto = require('crypto');
const {
  BOT_RISK_TIMEOUT_MS,
  BOT_RISK_SYNC_INTERVAL_MS,
  EDGE_ACCESS_SECRET
} = require('../config/env');
const LocalRiskDecisionCache = require('./LocalRiskDecisionCache');
const CredentialStore = require('./IntegrationCredentialStore');

const MAX_QUEUE_SIZE = 10000;
const BATCH_SIZE = 100;
let queue = [];
let flushTimer = null;
let decisionTimer = null;
let flushing = false;
let syncing = false;
let stopped = true;
let integrationDisabled = false;
let runtimeConfig = CredentialStore.botRiskConfig();
let lastConnectedAt = null;
let lastError = '';

function isPrivateHostname(hostname) {
  return hostname === 'localhost'
    || hostname === '127.0.0.1'
    || /^10\./.test(hostname)
    || /^192\.168\./.test(hostname)
    || /^172\.(1[6-9]|2\d|3[01])\./.test(hostname);
}

function normalizeConfig(input = {}, current = runtimeConfig) {
  const enabledValue = input.enabled === undefined ? current.enabled : input.enabled;
  const enabled = enabledValue === true || ['1', 'true', 'on', 'yes'].includes(String(enabledValue).toLowerCase());
  const connectionType = String(input.connectionType || input.connection_type || current.connectionType || 'https').trim().toLowerCase();
  const baseUrl = String(input.baseUrl || input.base_url || current.baseUrl || '').trim().replace(/\/$/, '');
  const clientId = String(input.clientId || input.client_id || current.clientId || '').trim();
  const secret = String(input.secret || current.secret || '').trim();
  const siteKey = String(input.siteKey || input.site_key || current.siteKey || '').trim();
  const mode = String(input.mode || current.mode || 'observe').trim().toLowerCase();
  if (!['internal', 'https'].includes(connectionType)) throw new Error('连接方式只能是内网或 HTTPS 外网');
  if (!['observe', 'enforce'].includes(mode)) throw new Error('运行模式只能是观察或执行');
  if (mode === 'enforce' && EDGE_ACCESS_SECRET.length < 32) {
    throw new Error('执行模式需要先在服务器配置至少 32 位 EDGE_ACCESS_SECRET');
  }
  let parsed;
  try { parsed = new URL(baseUrl); } catch { throw new Error('风险中心地址格式不正确'); }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') {
    throw new Error('风险中心地址必须是纯 Origin，不能包含路径、账号或查询参数');
  }
  if (connectionType === 'https' && parsed.protocol !== 'https:') throw new Error('HTTPS 外网连接必须使用 https:// 地址');
  if (connectionType === 'internal'
    && !(parsed.protocol === 'https:' || (parsed.protocol === 'http:' && isPrivateHostname(parsed.hostname)))) {
    throw new Error('内网 HTTP 地址必须使用 localhost、127.0.0.1 或 RFC1918 私网 IP');
  }
  if (!/^[A-Za-z0-9_-]{3,64}$/.test(clientId)) throw new Error('Client ID 格式不正确');
  if (!/^[A-Za-z0-9_-]{3,64}$/.test(siteKey)) throw new Error('站点标识格式不正确');
  if (secret.length < 32 || secret.length > 512) throw new Error('Client Secret 长度必须为 32–512 位');
  return { enabled, connectionType, baseUrl, clientId, secret, siteKey, mode };
}

function enabled() {
  return runtimeConfig.enabled === true;
}

function subjectHash(visitorId) {
  return crypto.createHmac('sha256', runtimeConfig.secret || 'local-disabled-risk-client')
    .update(String(visitorId || ''))
    .digest('hex');
}

function canonical(method, pathAndQuery, timestamp, nonce, rawBody) {
  return [
    method.toUpperCase(),
    pathAndQuery,
    timestamp,
    nonce,
    crypto.createHash('sha256').update(rawBody).digest('hex')
  ].join('\n');
}

async function signedRequest(method, pathAndQuery, body, config = runtimeConfig) {
  const rawBody = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(18).toString('base64url');
  const signature = crypto.createHmac('sha256', config.secret)
    .update(canonical(method, pathAndQuery, timestamp, nonce, rawBody))
    .digest('hex');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), BOT_RISK_TIMEOUT_MS);
  try {
    const response = await fetch(`${config.baseUrl}${pathAndQuery}`, {
      method,
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        ...(rawBody.length ? { 'Content-Type': 'application/json' } : {}),
        'X-Risk-Client': config.clientId,
        'X-Risk-Site': config.siteKey,
        'X-Risk-Timestamp': timestamp,
        'X-Risk-Nonce': nonce,
        'X-Risk-Signature': signature
      },
      body: rawBody.length ? rawBody : undefined
    });
    if (!response.ok) {
      const error = new Error(`risk center returned ${response.status}`);
      error.status = response.status;
      throw error;
    }
    integrationDisabled = false;
    lastConnectedAt = new Date().toISOString();
    lastError = '';
    return response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function enqueue(visitorId, eventType, evidence = {}) {
  if (!enabled() || !visitorId) return false;
  const event = {
    eventId: crypto.randomUUID(),
    visitorHash: subjectHash(visitorId),
    eventType: String(eventType || '').slice(0, 64),
    occurredAt: Date.now(),
    evidence: evidence && typeof evidence === 'object' ? evidence : {}
  };
  if (!/^[a-z0-9_-]{2,64}$/i.test(event.eventType)) return false;
  if (queue.length >= MAX_QUEUE_SIZE) queue.shift();
  queue.push(event);
  if (queue.length >= BATCH_SIZE) void flush();
  return true;
}

async function flush() {
  if (!enabled() || flushing || !queue.length) return { sent: 0 };
  flushing = true;
  const batch = queue.splice(0, BATCH_SIZE);
  try {
    await signedRequest('POST', '/v1/events/batch', { events: batch });
    return { sent: batch.length };
  } catch (error) {
    if (error.status === 403) {
      integrationDisabled = true;
      LocalRiskDecisionCache.clear();
      return { sent: 0, dropped: batch.length, disabled: true };
    }
    queue = [...batch, ...queue].slice(0, MAX_QUEUE_SIZE);
    return { sent: 0, error: error.name === 'AbortError' ? 'timeout' : error.message };
  } finally {
    flushing = false;
  }
}

async function syncDecisions() {
  if (!enabled() || syncing) return { applied: 0 };
  syncing = true;
  try {
    const cursor = LocalRiskDecisionCache.getCursor();
    const result = await signedRequest('GET', `/v1/decisions/delta?cursor=${cursor}&limit=1000`);
    return { applied: LocalRiskDecisionCache.setMany(result?.data?.items || []) };
  } catch (error) {
    lastError = error.name === 'AbortError' ? '风险中心连接超时' : String(error.message || error);
    if (error.status === 403) {
      integrationDisabled = true;
      LocalRiskDecisionCache.clear();
      return { applied: 0, disabled: true };
    }
    return { applied: 0, error: error.name === 'AbortError' ? 'timeout' : error.message };
  } finally {
    syncing = false;
  }
}

function getDecision(visitorId) {
  if (!enabled() || !visitorId) return null;
  const hash = subjectHash(visitorId);
  const decision = LocalRiskDecisionCache.get(hash);
  if (!decision) return null;
  return { ...decision, subjectHash: hash, enforce: runtimeConfig.mode === 'enforce' };
}

function markChallengePassed(visitorId) {
  if (!visitorId) return;
  const hash = subjectHash(visitorId);
  LocalRiskDecisionCache.markChallengePassed(hash);
  enqueue(visitorId, 'challenge_passed');
}

function hasChallengeBypass(visitorId) {
  return visitorId ? LocalRiskDecisionCache.hasChallengeBypass(subjectHash(visitorId)) : false;
}

function start() {
  if (!enabled() || !stopped) return;
  stopped = false;
  flushTimer = setInterval(() => { void flush(); }, 1000);
  decisionTimer = setInterval(() => { void syncDecisions(); }, BOT_RISK_SYNC_INTERVAL_MS);
  flushTimer.unref?.();
  decisionTimer.unref?.();
  void syncDecisions();
}

async function testConfig(input) {
  const config = normalizeConfig(input);
  await signedRequest('GET', '/v1/decisions/delta?cursor=0&limit=1', undefined, config);
  return { connected: true, config };
}

async function saveAndReconfigure(input) {
  const config = normalizeConfig(input);
  if (config.enabled) await signedRequest('GET', '/v1/decisions/delta?cursor=0&limit=1', undefined, config);
  await CredentialStore.saveBotRisk(config);
  if (!stopped) await stop();
  runtimeConfig = config;
  queue = [];
  integrationDisabled = false;
  lastError = '';
  LocalRiskDecisionCache.clear();
  if (config.enabled) start();
  return status();
}

async function stop() {
  stopped = true;
  if (flushTimer) clearInterval(flushTimer);
  if (decisionTimer) clearInterval(decisionTimer);
  flushTimer = null;
  decisionTimer = null;
  return flush();
}

function status() {
  return {
    enabled: enabled(),
    mode: runtimeConfig.mode,
    connectionType: runtimeConfig.connectionType,
    baseUrl: runtimeConfig.baseUrl,
    clientId: runtimeConfig.clientId,
    siteKey: runtimeConfig.siteKey,
    secretConfigured: Boolean(runtimeConfig.secret),
    integrationDisabled,
    queued: queue.length,
    cursor: LocalRiskDecisionCache.getCursor(),
    lastConnectedAt,
    lastError: lastError ? '风险中心暂时不可用' : ''
  };
}

function isEnforced() { return enabled() && runtimeConfig.mode === 'enforce'; }

module.exports = {
  subjectHash,
  enqueue,
  flush,
  syncDecisions,
  getDecision,
  markChallengePassed,
  hasChallengeBypass,
  testConfig,
  saveAndReconfigure,
  isEnforced,
  start,
  stop,
  status,
  normalizeConfig
};
