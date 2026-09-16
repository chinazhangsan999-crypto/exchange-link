'use strict';

const fs = require('fs');
const path = require('path');
const { Blob } = require('buffer');
const CredentialStore = require('./IntegrationCredentialStore');
const CloudflareApiEdgeService = require('./CloudflareApiEdgeService');
const CloudflareFrontendModel = require('../models/CloudflareFrontendModel');
const crypto = require('crypto');
const FrontendOriginModel = require('../models/FrontendOriginModel');
const { FRONTEND_PROXY_SECRET } = require('../config/env');

const API_BASE = 'https://api.cloudflare.com/client/v4';
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const API_WORKER_SOURCE = path.join(PROJECT_ROOT, 'ops', 'api-edge', 'worker.js');
const ADMIN_WORKER_SOURCE = path.join(PROJECT_ROOT, 'ops', 'admin-edge', 'worker.js');
const HOSTNAME_PATTERN = /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const WORKER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
let modelReady;
const ensureModelReady = () => (modelReady ||= CloudflareFrontendModel.initializeCloudflareFrontendTables());

function tokenFingerprint(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex').slice(-8).toUpperCase();
}

function normalizeHttpsUrl(value, label) {
  let parsed;
  try { parsed = new URL(String(value || '').trim()); }
  catch { throw new Error(`${label}格式不正确`); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error(`${label}必须是仅含域名的 HTTPS 地址`);
  }
  return parsed.origin;
}

function normalizeHostname(value, label) {
  const hostname = String(value || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/\.$/, '');
  if (!HOSTNAME_PATTERN.test(hostname)) throw new Error(`${label}格式不正确`);
  return hostname;
}

function normalizeWorkerName(value, label) {
  const name = String(value || '').trim();
  if (!WORKER_PATTERN.test(name)) throw new Error(`${label}格式不正确`);
  return name;
}

function normalizeInput(input = {}) {
  const edge = CredentialStore.cloudflareApiEdgeConfig();
  const stored = CredentialStore.cloudflareBootstrapConfig();
  const accountId = String(input.accountId || edge.accountId || '').trim();
  const apiToken = String(input.apiToken || edge.apiToken || '').trim();
  if (!/^[a-f0-9]{32}$/i.test(accountId)) throw new Error('Cloudflare Account ID 格式不正确');
  if (apiToken.length < 20 || apiToken.length > 512) throw new Error('Cloudflare API Token 格式不正确');
  return {
    accountId,
    apiToken,
    originUrl: normalizeHttpsUrl(input.originUrl || stored.originUrl || 'https://origin-link.chinazhangsan.ccwu.cc', '源站地址'),
    apiDomain: normalizeHostname(input.apiDomain || stored.apiDomain || 'api-link.chinazhangsan.ccwu.cc', 'API 域名'),
    apiWorkerName: normalizeWorkerName(input.apiWorkerName || stored.apiWorkerName || edge.workerName || 'webring-api-test', 'API Worker 名称'),
    adminDomain: normalizeHostname(input.adminDomain || stored.adminDomain || 'houtai.chinazhangsan.ccwu.cc', '后台域名'),
    adminWorkerName: normalizeWorkerName(input.adminWorkerName || stored.adminWorkerName || 'webring-admin-edge', '后台 Worker 名称')
  };
}

function publicStatus() {
  const edge = CredentialStore.cloudflareApiEdgeConfig();
  const stored = CredentialStore.cloudflareBootstrapConfig();
  return {
    configured: Boolean(edge.accountId && edge.workerName && edge.apiToken && stored.apiDomain && stored.adminDomain),
    accountId: edge.accountId,
    apiTokenConfigured: Boolean(edge.apiToken),
    originUrl: stored.originUrl || 'https://origin-link.chinazhangsan.ccwu.cc',
    apiDomain: stored.apiDomain || 'api-link.chinazhangsan.ccwu.cc',
    apiWorkerName: stored.apiWorkerName || edge.workerName || 'webring-api-test',
    adminDomain: stored.adminDomain || 'houtai.chinazhangsan.ccwu.cc',
    adminWorkerName: stored.adminWorkerName || 'webring-admin-edge'
  };
}

async function overview() {
  await ensureModelReady();
  const status = publicStatus();
  let saved = await CloudflareFrontendModel.getCentralState();
  if (!saved && status.configured) {
    await CloudflareFrontendModel.saveCentralState({
      accountId: status.accountId, apiWorkerName: status.apiWorkerName, apiDomain: status.apiDomain,
      adminWorkerName: status.adminWorkerName, adminDomain: status.adminDomain,
      originUrl: status.originUrl, tokenStatus: 'unverified'
    });
    saved = await CloudflareFrontendModel.getCentralState();
  }
  const parse = value => { try { return value ? JSON.parse(value) : null; } catch { return null; } };
  return {
    ...status,
    tokenFingerprint: saved?.token_fingerprint || null,
    tokenStatus: saved?.token_status || (status.apiTokenConfigured ? 'unverified' : 'missing'),
    apiHealth: parse(saved?.api_health_json),
    adminHealth: parse(saved?.admin_health_json),
    lastError: saved?.last_error || null,
    lastVerifiedAt: saved?.last_verified_at || null,
    lastDeployedAt: saved?.last_deployed_at || null
  };
}

async function adoptStoredState() {
  await ensureModelReady();
  const status = publicStatus();
  if (!status.configured || await CloudflareFrontendModel.getCentralState()) return status;
  const edge = CredentialStore.cloudflareApiEdgeConfig();
  await CloudflareFrontendModel.saveCentralState({
    accountId: status.accountId, apiWorkerName: status.apiWorkerName, apiDomain: status.apiDomain,
    adminWorkerName: status.adminWorkerName, adminDomain: status.adminDomain,
    originUrl: status.originUrl, tokenFingerprint: tokenFingerprint(edge.apiToken), tokenStatus: 'unverified'
  });
  return status;
}

async function request(config, method, apiPath, { body, headers = {}, timeoutMs = 30_000 } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${API_BASE}${apiPath}`, {
      method,
      headers: { Authorization: `Bearer ${config.apiToken}`, ...headers },
      body,
      signal: controller.signal
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok || !payload?.success) {
      throw new Error(payload?.errors?.[0]?.message || `Cloudflare API 请求失败（HTTP ${response.status}）`);
    }
    return payload.result ?? {};
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('连接 Cloudflare API 超时');
    throw error;
  } finally { clearTimeout(timeout); }
}

async function listZones(config) {
  const zones = [];
  for (let page = 1; page <= 20; page += 1) {
    const result = await request(config, 'GET', `/zones?account.id=${encodeURIComponent(config.accountId)}&status=active&per_page=50&page=${page}`);
    const rows = Array.isArray(result) ? result : [];
    zones.push(...rows.map(row => String(row.name || '').toLowerCase()).filter(Boolean));
    if (rows.length < 50) break;
  }
  return [...new Set(zones)];
}

function zoneForHostname(hostname, zones) {
  return zones.filter(zone => hostname === zone || hostname.endsWith(`.${zone}`)).sort((a, b) => b.length - a.length)[0] || '';
}

async function ensureDomainAvailable(config, hostname, workerName) {
  const domains = await request(config, 'GET', `/accounts/${encodeURIComponent(config.accountId)}/workers/domains`);
  const current = (Array.isArray(domains) ? domains : []).find(item => String(item.hostname || '').toLowerCase() === hostname);
  const currentService = String(current?.service || current?.script || '');
  if (current && currentService && currentService !== workerName) {
    throw new Error(`${hostname} 已绑定到其他 Worker（${currentService}），已停止以避免覆盖`);
  }
}

async function uploadWorker(config, workerName, sourceFile, bindings) {
  const source = await fs.promises.readFile(sourceFile, 'utf8');
  const metadata = { main_module: 'worker.js', compatibility_date: '2026-09-14', bindings };
  const form = new FormData();
  form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }), 'metadata.json');
  form.append('worker.js', new Blob([source], { type: 'application/javascript+module' }), 'worker.js');
  await request(config, 'PUT', `/accounts/${encodeURIComponent(config.accountId)}/workers/scripts/${encodeURIComponent(workerName)}`, { body: form });
  await request(config, 'PUT', `/accounts/${encodeURIComponent(config.accountId)}/workers/scripts/${encodeURIComponent(workerName)}/secrets`, {
    body: JSON.stringify({ name: 'FRONTEND_PROXY_SECRET', text: FRONTEND_PROXY_SECRET, type: 'secret_text' }),
    headers: { 'Content-Type': 'application/json' }
  });
}

async function attachDomain(config, hostname, workerName, zoneName) {
  await request(config, 'PUT', `/accounts/${encodeURIComponent(config.accountId)}/workers/domains`, {
    body: JSON.stringify({ hostname, service: workerName, zone_name: zoneName }),
    headers: { 'Content-Type': 'application/json' }
  });
}

async function checkUrl(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(url, { redirect: 'manual', signal: controller.signal });
    return { reachable: response.status >= 200 && response.status < 500, status: response.status };
  } catch (error) {
    return { reachable: false, status: null, reason: error.name === 'AbortError' ? 'timeout' : 'pending_dns_or_tls' };
  } finally { clearTimeout(timeout); }
}

async function deploy(input = {}) {
  await ensureModelReady();
  if (input.confirmOverwrite !== true) throw new Error('请先确认允许创建或更新指定的两个 Worker');
  if (!FRONTEND_PROXY_SECRET || FRONTEND_PROXY_SECRET.length < 32) throw new Error('服务器未配置 FRONTEND_PROXY_SECRET，无法安全部署');
  const config = normalizeInput(input);
  const existingEdge = CredentialStore.cloudflareApiEdgeConfig();
  if (existingEdge.accountId && config.accountId !== existingEdge.accountId) {
    throw new Error('中央线路 Account ID 已锁定；请勿用首次建站表单覆盖现有账号');
  }
  await request(config, 'GET', '/user/tokens/verify');
  const zones = await listZones(config);
  const apiZone = zoneForHostname(config.apiDomain, zones);
  const adminZone = zoneForHostname(config.adminDomain, zones);
  if (!apiZone) throw new Error(`API 域名 ${config.apiDomain} 不属于此账号的 Active Zone`);
  if (!adminZone) throw new Error(`后台域名 ${config.adminDomain} 不属于此账号的 Active Zone`);
  await ensureDomainAvailable(config, config.apiDomain, config.apiWorkerName);
  await ensureDomainAvailable(config, config.adminDomain, config.adminWorkerName);

  const origins = CloudflareApiEdgeService.bindingOrigins(await FrontendOriginModel.listAllOrigins()).join(',');
  const steps = [];
  await uploadWorker(config, config.apiWorkerName, API_WORKER_SOURCE, [
    { name: 'API_ORIGIN', type: 'plain_text', text: config.originUrl },
    { name: 'ALLOWED_FRONTEND_ORIGINS', type: 'plain_text', text: origins },
    { name: 'MAX_SKEW_MS', type: 'plain_text', text: '30000' }
  ]);
  steps.push({ key: 'api_worker', label: 'API Worker 代码与密钥', ok: true });
  await attachDomain(config, config.apiDomain, config.apiWorkerName, apiZone);
  steps.push({ key: 'api_domain', label: 'API 自定义域名', ok: true });

  await uploadWorker(config, config.adminWorkerName, ADMIN_WORKER_SOURCE, [
    { name: 'API_ORIGIN', type: 'plain_text', text: config.originUrl }
  ]);
  steps.push({ key: 'admin_worker', label: '后台 Worker 代码与密钥', ok: true });
  await attachDomain(config, config.adminDomain, config.adminWorkerName, adminZone);
  steps.push({ key: 'admin_domain', label: '后台自定义域名', ok: true });

  await CredentialStore.saveCloudflareApiEdge({ accountId: config.accountId, workerName: config.apiWorkerName, apiToken: config.apiToken });
  await CredentialStore.saveCloudflareBootstrap(config);
  const [apiHealth, adminHealth] = await Promise.all([
    checkUrl(`https://${config.apiDomain}/api/health`),
    checkUrl(`https://${config.adminDomain}/admin`)
  ]);
  await CloudflareFrontendModel.saveCentralState({
    accountId: config.accountId, apiWorkerName: config.apiWorkerName, apiDomain: config.apiDomain,
    adminWorkerName: config.adminWorkerName, adminDomain: config.adminDomain, originUrl: config.originUrl,
    tokenFingerprint: tokenFingerprint(config.apiToken), tokenStatus: 'valid',
    apiHealth, adminHealth, verified: true, deployed: true
  });
  return {
    ...publicStatus(),
    steps,
    apiHealth,
    adminHealth,
    note: apiHealth.reachable && adminHealth.reachable ? '两个入口已可访问' : '部署已完成，DNS 或证书可能仍在生效'
  };
}

async function verifyConnection(input = {}) {
  await ensureModelReady();
  const config = normalizeInput(input);
  try {
    await request(config, 'GET', '/user/tokens/verify');
    const zones = await listZones(config);
    const [apiHealth, adminHealth] = await Promise.all([
      checkUrl(`https://${config.apiDomain}/api/health`),
      checkUrl(`https://${config.adminDomain}/admin`)
    ]);
    await CloudflareFrontendModel.saveCentralState({
      accountId: config.accountId, apiWorkerName: config.apiWorkerName, apiDomain: config.apiDomain,
      adminWorkerName: config.adminWorkerName, adminDomain: config.adminDomain, originUrl: config.originUrl,
      tokenFingerprint: tokenFingerprint(config.apiToken), tokenStatus: 'valid',
      apiHealth, adminHealth, verified: true
    });
    return { connected: true, zones, apiHealth, adminHealth };
  } catch (error) {
    const stored = publicStatus();
    await CloudflareFrontendModel.saveCentralState({
      accountId: stored.accountId, apiWorkerName: stored.apiWorkerName, apiDomain: stored.apiDomain,
      adminWorkerName: stored.adminWorkerName, adminDomain: stored.adminDomain, originUrl: stored.originUrl,
      tokenStatus: 'invalid', error: error.message, verified: true
    });
    throw error;
  }
}

async function redeployTarget(target) {
  await ensureModelReady();
  if (!['api', 'admin'].includes(target)) throw new Error('不支持的中央线路部署目标');
  const config = normalizeInput({});
  const zones = await listZones(config);
  if (target === 'api') {
    const zone = zoneForHostname(config.apiDomain, zones);
    if (!zone) throw new Error('API 域名不属于当前账号的 Active Zone');
    const origins = CloudflareApiEdgeService.bindingOrigins(await FrontendOriginModel.listAllOrigins()).join(',');
    await uploadWorker(config, config.apiWorkerName, API_WORKER_SOURCE, [
      { name: 'API_ORIGIN', type: 'plain_text', text: config.originUrl },
      { name: 'ALLOWED_FRONTEND_ORIGINS', type: 'plain_text', text: origins },
      { name: 'MAX_SKEW_MS', type: 'plain_text', text: '30000' }
    ]);
    await attachDomain(config, config.apiDomain, config.apiWorkerName, zone);
  } else {
    const zone = zoneForHostname(config.adminDomain, zones);
    if (!zone) throw new Error('后台域名不属于当前账号的 Active Zone');
    await uploadWorker(config, config.adminWorkerName, ADMIN_WORKER_SOURCE, [
      { name: 'API_ORIGIN', type: 'plain_text', text: config.originUrl }
    ]);
    await attachDomain(config, config.adminDomain, config.adminWorkerName, zone);
  }
  const checked = await verifyConnection({});
  await CloudflareFrontendModel.saveCentralState({
    accountId: config.accountId, apiWorkerName: config.apiWorkerName, apiDomain: config.apiDomain,
    adminWorkerName: config.adminWorkerName, adminDomain: config.adminDomain, originUrl: config.originUrl,
    tokenFingerprint: tokenFingerprint(config.apiToken), tokenStatus: 'valid',
    apiHealth: checked.apiHealth, adminHealth: checked.adminHealth, verified: true, deployed: true
  });
  return { target, ...checked };
}

module.exports = { publicStatus, overview, adoptStoredState, normalizeInput, deploy, verifyConnection, redeployTarget };
