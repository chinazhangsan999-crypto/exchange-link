'use strict';

const express = require('express');
const crypto = require('crypto');
const {
  PROTOCOL_VERSION,
  HEADERS,
  ALL_CAPABILITIES,
  assertCompatibleVersion,
  buildSiteAuthorization,
  parseSiteCredential,
  revisionEtag,
  createHeartbeat,
  validateConfigSnapshot,
  validateSuccessEnvelope,
  validateErrorEnvelope,
  validateHeartbeatResult,
  validateSsoRedeemRequest,
  validateSsoRedeemResult,
  ERROR_CODES
} = require('../shared-protocol');

function createControlCenterAgent(options) {
  const controlCenterUrl = String(options.controlCenterUrl || '').replace(/\/$/, '');
  const credential = String(options.credential || '');
  const parsedCredential = parseSiteCredential(credential);
  const fetchImpl = options.fetch || global.fetch;
  if (!controlCenterUrl || !parsedCredential || typeof fetchImpl !== 'function') throw new Error('站点 Agent 缺少总后台地址、有效凭据或 fetch');
  if (typeof options.applyConfig !== 'function') throw new Error('站点 Agent 必须提供 applyConfig 回调');
  if (typeof options.issueAdminToken !== 'function') throw new Error('站点 Agent 必须提供 issueAdminToken 回调');

  let etag = '';
  let appliedRevision = String(options.appliedRevision || '');
  let stopped = true;
  let timer = null;
  const exchanges = new Map();
  const exchangeTtlMs = 30_000;
  const maxPendingExchanges = 500;
  const adminPath = normalizeAdminPath(options.adminPath || '/admin');

  function noStore(res) {
    res.set({
      'cache-control': 'no-store, no-cache, must-revalidate, private',
      pragma: 'no-cache',
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff'
    });
  }

  function purgeExchanges(now = Date.now()) {
    for (const [digest, item] of exchanges) if (item.expiresAt < now) exchanges.delete(digest);
  }

  async function request(path, init = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(new Error('总后台请求超过 8 秒')), 8000);
    try {
      return await fetchImpl(`${controlCenterUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          [HEADERS.authorization]: buildSiteAuthorization(credential),
          [HEADERS.protocol]: PROTOCOL_VERSION,
          [HEADERS.requestId]: crypto.randomUUID(),
          accept: 'application/json',
          ...(init.headers || {})
        }
      });
    } finally { clearTimeout(timeout); }
  }

  function assertResponseProtocol(response) {
    return assertCompatibleVersion(response.headers.get(HEADERS.protocol));
  }

  async function responseError(response, fallback) {
    const payload = await response.json().catch(() => null);
    let verified = null;
    try { verified = validateErrorEnvelope(payload); } catch {}
    const error = new Error(verified?.message || `${fallback}（${response.status}）`);
    error.code = verified?.error_code || 'CONTROL_CENTER_REQUEST_FAILED';
    error.status = response.status;
    throw error;
  }

  async function heartbeat() {
    const body = createHeartbeat({
      agentVersion: options.agentVersion || '0.1.0',
      appliedRevision,
      capabilities: options.capabilities || ALL_CAPABILITIES,
      metadata: options.metadata?.() || {}
    });
    const response = await request('/api/agent/heartbeat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    assertResponseProtocol(response);
    if (!response.ok) await responseError(response, '站点心跳失败');
    const payload = validateSuccessEnvelope(await response.json());
    return validateHeartbeatResult(payload.data);
  }

  async function syncLocalAd(localAdId, data) {
    const response = await request(`/api/agent/local-ads/${encodeURIComponent(localAdId)}`, {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(data)
    });
    assertResponseProtocol(response);
    if (!response.ok && data?.ad_type === 'code' && response.status === 404) {
      const legacy = await request(`/api/agent/local-code-ads/${encodeURIComponent(localAdId)}`, {
        method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(data)
      });
      assertResponseProtocol(legacy);
      if (!legacy.ok) await responseError(legacy, '本站广告同步失败');
      return validateSuccessEnvelope(await legacy.json()).data;
    }
    if (!response.ok) await responseError(response, '本站广告同步失败');
    return validateSuccessEnvelope(await response.json()).data;
  }

  async function deleteLocalAd(localAdId) {
    const response = await request(`/api/agent/local-ads/${encodeURIComponent(localAdId)}`, { method: 'DELETE' });
    assertResponseProtocol(response);
    if (!response.ok && response.status === 404) {
      const legacy = await request(`/api/agent/local-code-ads/${encodeURIComponent(localAdId)}`, { method: 'DELETE' });
      assertResponseProtocol(legacy);
      if (!legacy.ok) await responseError(legacy, '本站广告删除同步失败');
      return validateSuccessEnvelope(await legacy.json()).data;
    }
    if (!response.ok) await responseError(response, '本站广告删除同步失败');
    return validateSuccessEnvelope(await response.json()).data;
  }

  const syncLocalCodeAd = syncLocalAd;
  const deleteLocalCodeAd = deleteLocalAd;

  async function syncConfig() {
    const headers = etag ? { 'if-none-match': etag } : {};
    const response = await request('/api/agent/config', { headers });
    assertResponseProtocol(response);
    if (response.status === 304) return { changed: false };
    if (!response.ok) await responseError(response, '配置同步失败');
    const payload = validateSuccessEnvelope(await response.json());
    const snapshot = validateConfigSnapshot(payload.data);
    if (String(snapshot.site_id) !== parsedCredential.siteId) throw new Error('配置快照与当前站点凭据不匹配');
    const expectedEtag = revisionEtag(snapshot.revision);
    const receivedEtag = response.headers.get('etag');
    const receivedRevision = response.headers.get(HEADERS.configRevision);
    if (receivedEtag !== expectedEtag || receivedRevision !== snapshot.revision) throw new Error('配置快照修订标识不一致');
    await options.applyConfig(snapshot);
    etag = expectedEtag;
    appliedRevision = snapshot.revision;
    return { changed: true, revision: snapshot.revision };
  }

  async function tick() {
    try {
      const results = await Promise.allSettled([
        heartbeat().then(result => { options.onHeartbeat?.(result); return result; }),
        syncConfig()
      ]);
      for (const result of results) if (result.status === 'rejected') options.onError?.(result.reason);
    }
    finally { if (!stopped) timer = setTimeout(tick, options.intervalMs || 60_000); }
  }

  function start() { if (!stopped) return; stopped = false; tick(); }
  function stop() { stopped = true; if (timer) clearTimeout(timer); }

  const router = express.Router();
  router.get('/login', (req, res) => {
    noStore(res);
    const nonce = crypto.randomBytes(18).toString('base64');
    res.set('content-security-policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`);
    return res.type('html').send(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>正在进入管理后台</title><style nonce="${nonce}">body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f8fafd;color:#1f2940;font:16px system-ui,"Microsoft YaHei",sans-serif}.card{width:min(420px,calc(100vw - 40px));padding:32px;border:1px solid #e4e7f0;border-radius:22px;background:#fff;box-shadow:0 18px 50px #25325014;text-align:center}p{color:#768097}.error{color:#bd3e47}</style></head><body><main class="card"><h1>正在验证统一登录</h1><p id="status">即将进入本站管理后台…</p></main><script nonce="${nonce}">(async()=>{const status=document.querySelector('#status');const match=/^#control-ticket=([^&]+)$/.exec(location.hash);history.replaceState(null,'',location.pathname+location.search);if(!match){status.className='error';status.textContent='登录票据缺失，请返回总后台重试';return}try{const response=await fetch('./sso',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json','accept':'application/json'},body:JSON.stringify({ticket:decodeURIComponent(match[1])})});const payload=await response.json();if(!response.ok||!payload.data?.redirect)throw new Error(payload.message||'统一登录失败');location.replace(payload.data.redirect)}catch(error){status.className='error';status.textContent=error.message||'统一登录失败，请返回总后台重试'}})();</script></body></html>`);
  });
  router.post('/sso', express.json({ limit: '4kb' }), async (req, res) => {
    noStore(res);
    try {
      const fetchSite = String(req.get('sec-fetch-site') || '').toLowerCase();
      if (fetchSite && !['same-origin', 'none'].includes(fetchSite)) return res.status(403).json({ code: 403, message: '拒绝跨站兑换登录票据', data: null });
      const ticket = String(req.body?.ticket || '');
      validateSsoRedeemRequest({ ticket });
      const response = await request('/api/agent/sso/redeem', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ticket }) });
      assertResponseProtocol(response);
      const payload = await response.json();
      if (!response.ok) return res.status(401).json({ code: 401, message: '总后台登录票据无效或已过期', data: null });
      const result = validateSsoRedeemResult(validateSuccessEnvelope(payload).data);
      purgeExchanges();
      if (exchanges.size >= maxPendingExchanges) return res.status(503).json({ code: 503, message: '登录请求过多，请稍后重试', data: null });
      const adminToken = String(await options.issueAdminToken(result.admin, {
        source: 'control_center',
        nonce: result.local_session_nonce
      }) || '');
      if (!adminToken || adminToken.length > 8192) throw new Error('导航站未能签发有效的本地管理员令牌');
      const exchangeCode = crypto.randomBytes(24).toString('base64url');
      exchanges.set(crypto.createHash('sha256').update(exchangeCode).digest('hex'), { adminToken, expiresAt: Date.now() + exchangeTtlMs });
      return res.json({ code: 200, data: { redirect: `${adminPath}#control-sso=${encodeURIComponent(exchangeCode)}` } });
    } catch (error) {
      options.onError?.(error);
      if (error?.code === ERROR_CODES.invalidTicket) return res.status(401).json({ code: 401, message: '总后台登录票据无效或已过期', data: null });
      return res.status(502).json({ code: 502, message: '暂时无法连接总后台', data: null });
    }
  });
  router.post('/session', express.json({ limit: '4kb' }), (req, res) => {
    noStore(res);
    const fetchSite = String(req.get('sec-fetch-site') || '').toLowerCase();
    if (fetchSite && !['same-origin', 'none'].includes(fetchSite)) return res.status(403).json({ code: 403, message: '拒绝跨站交换登录会话' });
    const code = String(req.body?.code || '');
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(code)) return res.status(401).json({ code: 401, message: '登录交换码无效或已过期' });
    const digest = crypto.createHash('sha256').update(code).digest('hex');
    const exchange = exchanges.get(digest);
    exchanges.delete(digest);
    if (!exchange || exchange.expiresAt < Date.now()) return res.status(401).json({ code: 401, message: '登录交换码无效或已过期' });
    return res.json({ code: 200, data: { token: exchange.adminToken, source: 'control_center' } });
  });

  const cleanup = setInterval(() => {
    purgeExchanges();
  }, 30_000);
  cleanup.unref();

  return {
    protocolVersion: PROTOCOL_VERSION,
    router,
    start,
    stop,
    heartbeat,
    syncConfig,
    syncLocalCodeAd,
    deleteLocalCodeAd,
    syncLocalAd,
    deleteLocalAd,
    destroy: () => { stop(); clearInterval(cleanup); exchanges.clear(); },
    getAppliedRevision: () => appliedRevision
  };
}

function normalizeAdminPath(value) {
  const candidate = String(value || '').trim();
  if (/^\/[A-Za-z0-9/_-]*$/.test(candidate)) return candidate;
  let url;
  try { url = new URL(candidate); }
  catch { throw new Error('站点 Agent 后台路径不合法'); }
  if (url.protocol !== 'https:'
    || url.username || url.password || url.search || url.hash
    || url.pathname !== '/admin') {
    throw new Error('站点 Agent 后台地址必须是 HTTPS 且路径为 /admin。');
  }
  return url.toString().replace(/\/$/, '');
}

module.exports = { createControlCenterAgent };
