'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
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
let inventoryTimer = null;
let inventoryStartupTimer = null;
let flushing = false;
let syncing = false;
let stopped = true;
let integrationDisabled = false;
let runtimeConfig = CredentialStore.botRiskConfig();
let lastConnectedAt = null;
let lastError = '';
let lastInventoryAt = null;
let lastInventoryError = '';
let lastAdvisorySyncAt = null;
let advisories = [];
const PROCESS_STARTED_AT = new Date().toISOString();
const PROJECT_ROOT = path.join(__dirname, '..', '..');

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

function packageVersion(name) {
  try {
    const lock = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, 'package-lock.json'), 'utf8'));
    return String(lock.packages?.[`node_modules/${name}`]?.version || lock.dependencies?.[name]?.version || '');
  } catch { return ''; }
}

function fileSha256(relativePath) {
  try { return crypto.createHash('sha256').update(fs.readFileSync(path.join(PROJECT_ROOT, relativePath))).digest('hex'); }
  catch { return ''; }
}

function botdAssetVersion() {
  try {
    const head = fs.readFileSync(path.join(PROJECT_ROOT, 'public/vendor/botd.esm.js'), 'utf8').slice(0, 500);
    return head.match(/Fingerprint BotD v([^\s]+)/i)?.[1] || '';
  } catch { return ''; }
}

const MAINTENANCE_PACKAGES = Object.freeze([
  ['alicloud-dns-sdk', '@alicloud/alidns20150109'],
  ['alicloud-openapi-client', '@alicloud/openapi-client'],
  ['aws-route53-sdk', '@aws-sdk/client-route-53'],
  ['archiver', 'archiver'],
  ['async-mutex', 'async-mutex'],
  ['axios', 'axios'],
  ['bcryptjs', 'bcryptjs'],
  ['botd', '@fingerprintjs/botd'],
  ['cheerio', 'cheerio'],
  ['connect-sqlite3', 'connect-sqlite3'],
  ['csv-parse', 'csv-parse'],
  ['express', 'express'],
  ['express-session', 'express-session'],
  ['isbot', 'isbot'],
  ['jsonwebtoken', 'jsonwebtoken'],
  ['lru-cache', 'lru-cache'],
  ['multer', 'multer'],
  ['node-cron', 'node-cron'],
  ['node-redis', 'redis'],
  ['sqlite3', 'sqlite3'],
  ['svg-captcha', 'svg-captcha'],
  ['tencentcloud-dnspod-sdk', 'tencentcloud-sdk-nodejs-dnspod'],
  ['tldts', 'tldts'],
  ['ua-parser-js', 'ua-parser-js']
]);

function gitCommit() {
  const explicit = String(process.env.APP_GIT_COMMIT || process.env.GIT_COMMIT || '').trim();
  if (explicit) return explicit.slice(0, 80);
  try {
    const dotGit = path.join(PROJECT_ROOT, '.git');
    const stat = fs.statSync(dotGit);
    const gitDir = stat.isDirectory() ? dotGit
      : path.resolve(PROJECT_ROOT, fs.readFileSync(dotGit, 'utf8').replace(/^gitdir:\s*/i, '').trim());
    const head = fs.readFileSync(path.join(gitDir, 'HEAD'), 'utf8').trim();
    if (!head.startsWith('ref: ')) return head.slice(0, 80);
    return fs.readFileSync(path.join(gitDir, head.slice(5)), 'utf8').trim().slice(0, 80);
  } catch { return ''; }
}

function buildRuntimeInventory() {
  const app = require('../../package.json');
  const components = MAINTENANCE_PACKAGES.map(([key, packageName]) => ({
    key,
    packageVersion: packageVersion(packageName)
  }));
  const botd = components.find(item => item.key === 'botd');
  if (botd) {
    botd.assetVersion = botdAssetVersion();
    botd.assetSha256 = fileSha256('public/vendor/botd.esm.js');
  }
  components.unshift({ key: 'nodejs', packageVersion: process.version.replace(/^v/, '') });
  return {
    schemaVersion: 'inventory-v1',
    appVersion: String(app.version || ''),
    gitCommit: gitCommit(),
    nodeVersion: process.version,
    riskProtocolVersion: 'risk-agent-v1',
    deployedAt: String(process.env.APP_DEPLOYED_AT || PROCESS_STARTED_AT),
    components,
    capabilities: ['botd', 'crawler_ua', 'browser_pow', 'read_token', 'token_replay_v2', 'risk_decision_sync']
  };
}

async function reportInventory() {
  if (!enabled()) return { reported: false, reason: 'disabled' };
  try {
    const result = await signedRequest('POST', '/v1/agent/inventory', buildRuntimeInventory());
    lastInventoryAt = result?.data?.reportedAt || new Date().toISOString();
    lastInventoryError = '';
    return { reported: true, data: result?.data };
  } catch (error) {
    lastInventoryError = error.name === 'AbortError' ? '运行清单上报超时' : String(error.message || error);
    return { reported: false, error: lastInventoryError };
  }
}

async function getAdvisories() {
  if (!enabled()) return [];
  const result = await signedRequest('GET', '/v1/agent/advisories');
  return result?.data || [];
}

async function reportTestResult(input) {
  if (!enabled()) return { reported: false, reason: 'disabled' };
  const result = await signedRequest('POST', '/v1/agent/test-results', input);
  return { reported: true, data: result?.data };
}

async function syncMaintenanceState() {
  const inventory = await reportInventory();
  if (!inventory.reported) return inventory;
  try {
    advisories = await getAdvisories();
    lastAdvisorySyncAt = new Date().toISOString();
    return { ...inventory, advisories: advisories.length };
  } catch (error) {
    lastInventoryError = error.name === 'AbortError' ? '更新建议同步超时' : String(error.message || error);
    return { ...inventory, advisoryError: lastInventoryError };
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
  inventoryTimer = setInterval(() => { void syncMaintenanceState(); }, 6 * 60 * 60 * 1000);
  inventoryStartupTimer = setTimeout(() => { void syncMaintenanceState(); }, 5000);
  flushTimer.unref?.();
  decisionTimer.unref?.();
  inventoryTimer.unref?.();
  inventoryStartupTimer.unref?.();
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
  if (inventoryTimer) clearInterval(inventoryTimer);
  if (inventoryStartupTimer) clearTimeout(inventoryStartupTimer);
  flushTimer = null;
  decisionTimer = null;
  inventoryTimer = null;
  inventoryStartupTimer = null;
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
    lastInventoryAt,
    lastAdvisorySyncAt,
    advisoryCount: advisories.length,
    lastInventoryError: lastInventoryError ? '运行清单暂时未能上报' : '',
    lastError: lastError ? '风险中心暂时不可用' : ''
  };
}

function isEnforced() { return enabled() && runtimeConfig.mode === 'enforce'; }

module.exports = {
  subjectHash,
  enqueue,
  flush,
  syncDecisions,
  buildRuntimeInventory,
  reportInventory,
  getAdvisories,
  reportTestResult,
  syncMaintenanceState,
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
