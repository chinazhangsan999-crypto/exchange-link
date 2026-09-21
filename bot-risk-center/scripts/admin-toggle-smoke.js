'use strict';

const crypto = require('crypto');
const { sign } = require('../src/security/hmac');

const baseUrl = String(process.env.RISK_SMOKE_BASE_URL || 'http://127.0.0.1:4100').replace(/\/$/, '');
const adminUsername = String(process.env.RISK_SMOKE_ADMIN_USERNAME || 'admin');
const adminPassword = String(process.env.RISK_SMOKE_ADMIN_PASSWORD || 'admin123');
const clientId = String(process.env.RISK_SMOKE_CLIENT_ID || '');
const clientSecret = String(process.env.RISK_SMOKE_CLIENT_SECRET || '');
const siteKey = String(process.env.RISK_SMOKE_SITE_KEY || clientId);

if (!adminUsername || !adminPassword || !clientId || clientSecret.length < 32 || !siteKey) {
  throw new Error('缺少风险中心后台或客户端烟雾测试环境变量');
}

async function jsonRequest(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const result = await response.json().catch(() => null);
  return { response, result };
}

async function signedRequest(path, body) {
  const rawBody = Buffer.from(JSON.stringify(body));
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(16).toString('hex');
  const signature = sign(clientSecret, {
    method: 'POST', pathAndQuery: path, timestamp, nonce, body: rawBody
  });
  return jsonRequest(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Risk-Client': clientId,
      'X-Risk-Site': siteKey,
      'X-Risk-Timestamp': timestamp,
      'X-Risk-Nonce': nonce,
      'X-Risk-Signature': signature
    },
    body: rawBody
  });
}

async function main() {
  const before = await signedRequest('/v1/evaluate', { visitorHash: 'a'.repeat(64) });
  if (!before.response.ok) throw new Error(`初始客户端鉴权失败: ${before.response.status}`);

  const login = await jsonRequest('/admin/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: adminUsername, password: adminPassword })
  });
  if (!login.response.ok) throw new Error(`后台登录失败: ${login.response.status}`);
  const csrfToken = login.result?.data?.csrfToken;
  const setCookie = login.response.headers.getSetCookie?.()[0] || login.response.headers.get('set-cookie');
  const cookie = String(setCookie || '').split(';')[0];
  if (!csrfToken || !cookie) throw new Error('后台登录未签发 Cookie 或 CSRF Token');

  async function setStatus(enabled) {
    return jsonRequest(`/admin/api/sites/${encodeURIComponent(siteKey)}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, Cookie: cookie },
      body: JSON.stringify({ enabled })
    });
  }

  const disabled = await setStatus(false);
  if (!disabled.response.ok || disabled.result?.data?.enabled !== false) {
    throw new Error(`关闭站点失败: ${disabled.response.status}`);
  }

  const blocked = await signedRequest('/v1/evaluate', { visitorHash: 'b'.repeat(64) });
  if (blocked.response.status !== 403) {
    await setStatus(true);
    throw new Error(`关闭后预期 403，实际为 ${blocked.response.status}`);
  }

  const enabled = await setStatus(true);
  if (!enabled.response.ok || enabled.result?.data?.enabled !== true) {
    throw new Error(`重新开启站点失败: ${enabled.response.status}`);
  }

  const restored = await signedRequest('/v1/evaluate', { visitorHash: 'c'.repeat(64) });
  if (!restored.response.ok) throw new Error(`重新开启后客户端未恢复: ${restored.response.status}`);

  process.stdout.write(JSON.stringify({ login: 200, disabled: 403, restored: 200, siteKey }) + '\n');
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
