'use strict';

const CredentialStore = require('./IntegrationCredentialStore');

const API_BASE = 'https://api.cloudflare.com/client/v4';
const ORIGIN_BINDING_NAME = 'ALLOWED_FRONTEND_ORIGINS';

function normalizeWorkerName(value, label) {
  const normalized = String(value || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(normalized)) throw new Error(`${label}格式不正确`);
  return normalized;
}

function validateConfig(input = {}, stored = CredentialStore.cloudflareApiEdgeConfig()) {
  const accountId = String(input.accountId ?? stored.accountId ?? '').trim();
  const workerName = String(input.workerName ?? stored.workerName ?? '').trim();
  // 留空意味着保留已安全保存的 Token，绝不把 Token 回显到浏览器。
  const apiToken = String(input.apiToken || stored.apiToken || '').trim();

  if (!/^[a-f0-9]{32}$/i.test(accountId)) throw new Error('Cloudflare Account ID 格式不正确');
  normalizeWorkerName(workerName, 'API Edge Worker 名称');
  if (apiToken.length < 20 || apiToken.length > 512) throw new Error('Cloudflare API Token 格式不正确');
  return { accountId, workerName, apiToken };
}

function publicStatus() {
  const config = CredentialStore.cloudflareApiEdgeConfig();
  return {
    configured: Boolean(config.accountId && config.workerName && config.apiToken),
    accountId: config.accountId,
    workerName: config.workerName,
    apiTokenConfigured: Boolean(config.apiToken)
  };
}

async function cloudflareRequest(config, method, path, body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const isFormData = typeof FormData !== 'undefined' && body instanceof FormData;
    const response = await fetch(`${API_BASE}/accounts/${encodeURIComponent(config.accountId)}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${config.apiToken}`,
        ...(body && !isFormData ? { 'Content-Type': 'application/json' } : {})
      },
      body: body ? (isFormData ? body : JSON.stringify(body)) : undefined,
      signal: controller.signal
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok || !payload?.success) {
      const message = payload?.errors?.[0]?.message || `Cloudflare API 请求失败（HTTP ${response.status}）`;
      throw new Error(message);
    }
    return payload.result || {};
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('连接 Cloudflare API 超时');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function bindingOrigins(items) {
  const now = Date.now();
  return items
    .filter(item => item && item.enabled !== false && Number(item.enabled) !== 0)
    .filter(item => {
      const expiresAt = item.expiresAt ?? item.expires_at;
      return !expiresAt || new Date(expiresAt).getTime() > now;
    })
    .map(item => String(item.origin || '').trim().toLowerCase().replace(/\/$/, ''))
    .filter(Boolean)
    .sort();
}

async function getSettings(config) {
  return cloudflareRequest(config, 'GET', `/workers/scripts/${encodeURIComponent(config.workerName)}/settings`);
}

async function testConfig(input = {}) {
  const config = validateConfig(input);
  await getSettings(config);
  return { accountId: config.accountId, workerName: config.workerName };
}

async function saveAndVerify(input = {}) {
  const stored = CredentialStore.cloudflareApiEdgeConfig();
  const config = validateConfig(input);
  if (stored.accountId && config.accountId !== stored.accountId) {
    throw new Error('中央线路 Account ID 已锁定；更换账号必须执行中央线路迁移，不能覆盖现有配置');
  }
  await getSettings(config);
  await CredentialStore.saveCloudflareApiEdge(config);
  return publicStatus();
}

async function syncAllowedOrigins(items) {
  const status = publicStatus();
  if (!status.configured) return { synchronized: false, reason: 'unconfigured' };

  const config = validateConfig({}, CredentialStore.cloudflareApiEdgeConfig());
  const settings = await getSettings(config);
  const bindings = Array.isArray(settings.bindings) ? settings.bindings : [];
  const nextBindings = bindings.filter(binding => binding?.name !== ORIGIN_BINDING_NAME);
  nextBindings.push({
    name: ORIGIN_BINDING_NAME,
    type: 'plain_text',
    text: bindingOrigins(items).join(',')
  });

  // Cloudflare 的 Worker Settings PATCH 接口只接受 multipart/form-data，
  // settings 字段内再携带 JSON。不要手动设置 Content-Type，由 FormData
  // 生成带 boundary 的完整请求头。
  const form = new FormData();
  form.append('settings', new Blob([JSON.stringify({ bindings: nextBindings })], { type: 'application/json' }), 'settings.json');
  await cloudflareRequest(config, 'PATCH', `/workers/scripts/${encodeURIComponent(config.workerName)}/settings`, form);
  return { synchronized: true, origins: bindingOrigins(items) };
}

module.exports = {
  publicStatus,
  testConfig,
  saveAndVerify,
  syncAllowedOrigins,
  validateConfig,
  bindingOrigins
};
