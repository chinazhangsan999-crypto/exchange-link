'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { LRUCache } = require('lru-cache');
const { GUEST_JWT_SECRET, IS_PRODUCTION, TRAFFIC_DEBUG } = require('../config/env');
const { getClientIp, parseHostname } = require('../utils/network');

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const SECURITY_ALERT_COOLDOWN_MS = 5 * 60 * 1000;
const GUEST_VERIFY_COOKIE = 'guest_verify_token';
const GUEST_VISITOR_COOKIE = 'guest_visitor_id';
const PENDING_TRAFFIC_REFERER_COOKIE = 'pending_traffic_referer';
const PENDING_TRAFFIC_SOURCE_COOKIE = 'pending_inflow_source';
const VERIFY_NONCE_TTL_MS = 60 * 1000;
const VERIFY_COOKIE_TTL_MS = 12 * 60 * 60 * 1000;
const VISITOR_COOKIE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const RISK_CHALLENGE_TTL_MS = 60 * 60 * 1000;
const PENDING_TRAFFIC_REFERER_TTL_SECONDS = 5 * 60;
const PENDING_TRAFFIC_SOURCE_TTL_SECONDS = 15 * 60;

// 容量受控的内存状态：LRU 自动淘汰，避免恶意 IP/端点扫描无限占用内存。
const visitRateLimitCache = new LRUCache({ max: 100000, ttl: RATE_LIMIT_WINDOW_MS });
const securityAlertCache = new LRUCache({ max: 100000, ttl: SECURITY_ALERT_COOLDOWN_MS });
const endpointRateLimitCache = new LRUCache({ max: 100000, ttl: 60 * 60 * 1000 });
const verificationNonces = new LRUCache({ max: 50000, ttl: VERIFY_NONCE_TTL_MS });
const riskWindowCache = new LRUCache({ max: 100000, ttl: 60 * 60 * 1000 });
const pendingRiskChallenges = new LRUCache({ max: 100000, ttl: RISK_CHALLENGE_TTL_MS });

function trafficDebug(message) {
  if (TRAFFIC_DEBUG) console.log(`[流量排查] ${message}`);
}

function readCookie(req, name, decode = true) {
  const pair = String(req.headers.cookie || '')
    .split(';')
    .map(item => item.trim())
    .find(item => item.startsWith(`${name}=`));
  if (!pair) return '';
  const value = pair.slice(name.length + 1);
  if (!decode) return value;
  try { return decodeURIComponent(value); } catch { return ''; }
}

/** 保留原始 Cookie 文本，调用端按原有方式决定是否 decodeURIComponent。 */
function getCookie(req, name) {
  return readCookie(req, name, false);
}

function readGuestVerification(req) {
  try {
    const payload = jwt.verify(readCookie(req, GUEST_VERIFY_COOKIE), GUEST_JWT_SECRET, { algorithms: ['HS256'] });
    return payload?.scope === 'guest-verified'
      && payload?.role === 'guest'
      && payload?.type === 'guest-verification'
      ? payload
      : null;
  } catch {
    return null;
  }
}

function readVisitorId(req) {
  try {
    const payload = jwt.verify(readCookie(req, GUEST_VISITOR_COOKIE), GUEST_JWT_SECRET, { algorithms: ['HS256'] });
    return payload?.scope === 'guest-visitor'
      && payload?.type === 'guest-visitor'
      && typeof payload?.visitorId === 'string'
      && payload.visitorId.length >= 16
      ? payload.visitorId
      : '';
  } catch {
    return '';
  }
}

/**
 * 为风险计数签发稳定的匿名访客标识。它不是验证凭证，首次访问和 Cookie 缺失都不会被拦截。
 */
function ensureVisitorIdentity(req, res) {
  if (req.visitorId) return req.visitorId;
  const existing = readVisitorId(req);
  const visitorId = existing || crypto.randomBytes(18).toString('base64url');
  req.visitorId = visitorId;
  if (!existing) {
    const token = jwt.sign(
      { scope: 'guest-visitor', type: 'guest-visitor', visitorId },
      GUEST_JWT_SECRET,
      { expiresIn: Math.floor(VISITOR_COOKIE_TTL_MS / 1000), algorithm: 'HS256' }
    );
    res.cookie(GUEST_VISITOR_COOKIE, token, {
      maxAge: VISITOR_COOKIE_TTL_MS,
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PRODUCTION,
      path: '/'
    });
  }
  return visitorId;
}

function requestIdentityKey(req) {
  return crypto.createHash('sha256')
    .update(`${req.visitorId || readVisitorId(req)}|${getClientIp(req) || 'unknown'}|${requestUaHash(req)}`)
    .digest('hex');
}

function incrementRiskWindow(key, windowMs) {
  const now = Date.now();
  const existing = riskWindowCache.get(key);
  if (!existing || now >= existing.resetAt) {
    const record = { count: 1, resetAt: now + windowMs, challengeTriggeredAt: 0 };
    riskWindowCache.set(key, record, { ttl: windowMs });
    return record;
  }
  const record = { ...existing, count: Number(existing.count || 0) + 1 };
  riskWindowCache.set(key, record, { ttl: Math.max(1, record.resetAt - now) });
  return record;
}

function saveRiskWindow(key, record) {
  riskWindowCache.set(key, record, { ttl: Math.max(1, Number(record.resetAt || 0) - Date.now()) });
}

function pendingRiskKey(req) {
  return `risk:${requestIdentityKey(req)}`;
}

function raisePendingRiskChallenge(req, type, triggeredAt = Date.now()) {
  const key = pendingRiskKey(req);
  const existing = pendingRiskChallenges.get(key);
  if (existing && Number(existing.triggeredAt) >= Number(triggeredAt)) return existing;
  const challenge = {
    type: String(type || 'request_risk'),
    triggeredAt: Number(triggeredAt) || Date.now(),
    expiresAt: Date.now() + RISK_CHALLENGE_TTL_MS
  };
  pendingRiskChallenges.set(key, challenge, { ttl: RISK_CHALLENGE_TTL_MS });
  return challenge;
}

function getPendingRiskChallenge(req) {
  return pendingRiskChallenges.get(pendingRiskKey(req)) || null;
}

function hasFreshGuestVerification(req, challenge = getPendingRiskChallenge(req)) {
  if (!challenge) return true;
  const payload = readGuestVerification(req);
  return Boolean(payload
    && payload.visitorId === (req.visitorId || readVisitorId(req))
    && Number(payload.verifiedAt || 0) >= Number(challenge.triggeredAt || 0));
}

function readPendingTrafficReferer(req) {
  try {
    const payload = jwt.verify(readCookie(req, PENDING_TRAFFIC_REFERER_COOKIE), GUEST_JWT_SECRET, { algorithms: ['HS256'] });
    return payload?.scope === 'pending-traffic-referer'
      && payload?.role === 'guest'
      && payload?.type === 'pending-traffic-referer'
      && payload?.ip === getClientIp(req)
      ? String(payload.referer || '')
      : '';
  } catch {
    return '';
  }
}

function clearPendingTrafficReferer(res) {
  res.cookie(PENDING_TRAFFIC_REFERER_COOKIE, '', {
    maxAge: 0,
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PRODUCTION,
    path: '/'
  });
}

function requestUaHash(req) {
  return crypto.createHash('sha256')
    .update(String(req.get('user-agent') || '').slice(0, 300))
    .digest('hex');
}

/** 保存已解析的 SID/Domain 归属，用于跨越清理 URL 和滑块验证流程。 */
function storePendingTrafficSource(req, res, source) {
  const token = jwt.sign({
    scope: 'pending-inflow-source',
    role: 'guest',
    type: 'pending-inflow-source',
    partnerId: Number(source.partnerId),
    sourceTokenId: Number(source.sourceTokenId) || null,
    sidPartnerId: Number(source.sidPartnerId) || null,
    domainPartnerId: Number(source.domainPartnerId) || null,
    method: String(source.method || '').slice(0, 64),
    observedDomain: String(source.observedDomain || '').slice(0, 253),
    referer: String(source.referer || '').slice(0, 2048),
    ip: getClientIp(req),
    uaHash: requestUaHash(req)
  }, GUEST_JWT_SECRET, { expiresIn: PENDING_TRAFFIC_SOURCE_TTL_SECONDS, algorithm: 'HS256' });
  res.cookie(PENDING_TRAFFIC_SOURCE_COOKIE, token, {
    maxAge: PENDING_TRAFFIC_SOURCE_TTL_SECONDS * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PRODUCTION,
    path: '/'
  });
}

function readPendingTrafficSource(req) {
  try {
    const payload = jwt.verify(
      readCookie(req, PENDING_TRAFFIC_SOURCE_COOKIE),
      GUEST_JWT_SECRET,
      { algorithms: ['HS256'] }
    );
    if (payload?.scope !== 'pending-inflow-source'
      || payload?.role !== 'guest'
      || payload?.type !== 'pending-inflow-source'
      || payload?.ip !== getClientIp(req)
      || payload?.uaHash !== requestUaHash(req)
      || !Number.isSafeInteger(Number(payload?.partnerId))) return null;
    return {
      partnerId: Number(payload.partnerId),
      sourceTokenId: Number(payload.sourceTokenId) || null,
      sidPartnerId: Number(payload.sidPartnerId) || null,
      domainPartnerId: Number(payload.domainPartnerId) || null,
      method: String(payload.method || ''),
      observedDomain: String(payload.observedDomain || ''),
      referer: String(payload.referer || '')
    };
  } catch {
    return null;
  }
}

function clearPendingTrafficSource(res) {
  res.cookie(PENDING_TRAFFIC_SOURCE_COOKIE, '', {
    maxAge: 0,
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PRODUCTION,
    path: '/'
  });
}

/**
 * 在滑块跳转前暂存外部 Referer。这里只签发短效 HttpOnly JWT，绝不写入流量表。
 * req 标记用于避免前置中间件与门禁重复设置同一个 Cookie。
 */
function storePendingTrafficReferer(req, res, referer = '') {
  const rawReferer = String(referer || req.get('Referer') || '').trim();
  if (!parseHostname(rawReferer)) return false;

  const token = jwt.sign(
    {
      scope: 'pending-traffic-referer',
      role: 'guest',
      type: 'pending-traffic-referer',
      referer: rawReferer,
      ip: getClientIp(req)
    },
    GUEST_JWT_SECRET,
    { expiresIn: PENDING_TRAFFIC_REFERER_TTL_SECONDS, algorithm: 'HS256' }
  );
  res.cookie(PENDING_TRAFFIC_REFERER_COOKIE, token, {
    maxAge: PENDING_TRAFFIC_REFERER_TTL_SECONDS * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PRODUCTION,
    path: '/'
  });
  req.pendingTrafficRefererStored = true;
  trafficDebug(`滑块中转：已暂存原始 Referer=${rawReferer}`);
  return true;
}

function isVerificationExempt(req) {
  const pathname = req.path;
  return pathname === '/verify.html'
    || pathname === '/verify.css'
    || pathname === '/verify.js'
    // 防失联发布页必须使用精确路径白名单，不能被滑块门禁拦截。
    || pathname === '/publish.html'
    || pathname === '/publish.css'
    || pathname === '/publish.js'
    || pathname === '/showcase.css'
    || pathname === '/showcase.js'
    || pathname === '/api/mirrors'
    || pathname === '/analytics.js'
    || pathname === '/favicon.ico'
    || pathname === '/manifest.json'
    || pathname === '/sw.js'
    || pathname.startsWith('/icons/')
    || pathname.startsWith('/uploads/logo/')
    || pathname.startsWith('/api/verify/')
    || pathname === '/api/health'
    // 验证页也需要读取公开品牌配置，以展示管理员设置的统一 Logo。
    || pathname === '/api/config/public'
    || pathname === '/api/config'
    || pathname === '/api/analytics/config'
    || pathname.startsWith('/admin')
    || pathname.startsWith('/api/admin');
}

function isStaticAssetPath(pathname) {
  return /\.(?:css|js|mjs|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|map)$/i.test(String(pathname || ''));
}

function isDynamicRiskRequest(req) {
  if (isVerificationExempt(req) || isStaticAssetPath(req.path)) return false;
  if (req.path === '/' || req.path === '/go' || req.path.startsWith('/r/')) return true;
  if (req.path.startsWith('/api/')) return true;
  return req.method === 'GET' && String(req.get('accept') || '').includes('text/html');
}

function sendRateLimitResponse(res, resetAt) {
  const retryAfter = Math.max(1, Math.ceil((Number(resetAt || 0) - Date.now()) / 1000));
  res.setHeader('Retry-After', String(retryAfter));
  return res.status(429).json({ code: 429, msg: `请求过于频繁，请 ${retryAfter} 秒后再试`, data: null });
}

/**
 * 只观察动态请求并签发匿名 visitor_id。首页与公开页面永不因风险记录跳转验证页；
 * 极端请求量仅限制当前动态 API，请求静态资源不进入计数。
 */
function observeRequestRisk(req, res, next) {
  ensureVisitorIdentity(req, res);
  if (!isDynamicRiskRequest(req)) return next();

  const now = Date.now();
  const identity = requestIdentityKey(req);
  const ip = getClientIp(req) || 'unknown';
  const client10sKey = `dynamic-client-10s:${identity}`;
  const client60sKey = `dynamic-client-60s:${identity}`;
  const ip10sKey = `dynamic-ip-10s:${ip}`;
  const ip60sKey = `dynamic-ip-60s:${ip}`;
  const client10s = incrementRiskWindow(client10sKey, 10 * 1000);
  const client60s = incrementRiskWindow(client60sKey, 60 * 1000);
  const ip10s = incrementRiskWindow(ip10sKey, 10 * 1000);
  const ip60s = incrementRiskWindow(ip60sKey, 60 * 1000);

  const riskRecord = client10s.count > 30 ? { key: client10sKey, record: client10s }
    : client60s.count > 120 ? { key: client60sKey, record: client60s }
      : ip10s.count > 80 ? { key: ip10sKey, record: ip10s }
        : null;
  if (riskRecord && !riskRecord.record.challengeTriggeredAt) {
    riskRecord.record.challengeTriggeredAt = now;
    saveRiskWindow(riskRecord.key, riskRecord.record);
    raisePendingRiskChallenge(req, 'dynamic_request_burst', now);
  }

  // 浏览首页永远放行；极端 IP 总量只对动态 API 和出站操作返回 429。
  if (ip60s.count > 300 && (req.path.startsWith('/api/') || req.path === '/go')) {
    return sendRateLimitResponse(res, ip60s.resetAt);
  }
  return next();
}

/** 友链申请：第 5 次触发验证；同一 IP 一小时第 11 次开始硬限流。 */
function applyRiskProtection(req, res, next) {
  ensureVisitorIdentity(req, res);
  const now = Date.now();
  const ip = getClientIp(req) || 'unknown';
  const hardRecord = incrementRiskWindow(`apply-ip:${ip}`, 60 * 60 * 1000);
  if (hardRecord.count > 10) return sendRateLimitResponse(res, hardRecord.resetAt);

  const clientKey = `apply-client:${requestIdentityKey(req)}`;
  const clientRecord = incrementRiskWindow(clientKey, 60 * 60 * 1000);
  if (clientRecord.count >= 5) {
    if (!clientRecord.challengeTriggeredAt) {
      clientRecord.challengeTriggeredAt = now;
      saveRiskWindow(clientKey, clientRecord);
    }
    raisePendingRiskChallenge(req, 'link_apply', clientRecord.challengeTriggeredAt);
  }
  return next();
}

/** /go 使用独立计数桶；风险判断发生在出站日志写入之前。 */
function outboundRiskProtection(req, res, next) {
  ensureVisitorIdentity(req, res);
  const now = Date.now();
  const ip = getClientIp(req) || 'unknown';
  const identity = requestIdentityKey(req);
  const targetId = String(req.query?.id || 'unknown').slice(0, 32);
  const hardRecord = incrementRiskWindow(`outbound-ip-10m:${ip}`, 10 * 60 * 1000);
  if (hardRecord.count > 30) return sendRateLimitResponse(res, hardRecord.resetAt);

  const clientKey = `outbound-client-60s:${identity}`;
  const targetKey = `outbound-target-30s:${identity}:${targetId}`;
  const clientRecord = incrementRiskWindow(clientKey, 60 * 1000);
  const targetRecord = incrementRiskWindow(targetKey, 30 * 1000);
  const riskRecord = targetRecord.count >= 5 ? { key: targetKey, record: targetRecord, type: 'repeated_outbound_target' }
    : clientRecord.count >= 10 ? { key: clientKey, record: clientRecord, type: 'outbound_burst' }
      : null;
  if (riskRecord) {
    if (!riskRecord.record.challengeTriggeredAt) {
      riskRecord.record.challengeTriggeredAt = now;
      saveRiskWindow(riskRecord.key, riskRecord.record);
    }
    raisePendingRiskChallenge(req, riskRecord.type, riskRecord.record.challengeTriggeredAt);
  }
  return next();
}

/** 仅挂在敏感操作上；普通首页和公开浏览永远不会进入此门禁。 */
function adaptiveVerificationGate(req, res, next) {
  if (isVerificationExempt(req)) return next();
  const challenge = getPendingRiskChallenge(req);
  if (!challenge || hasFreshGuestVerification(req, challenge)) return next();

  const verificationUrl = `/verify.html?target=${encodeURIComponent(req.originalUrl || '/')}`;
  if (req.method === 'GET' && req.path === '/go') return res.redirect(302, verificationUrl);
  return res.status(428).json({
    code: 428,
    msg: '需要完成安全验证',
    data: {
      verificationUrl: req.path === '/api/links/apply'
        ? '/verify.html?target=%2F%3Fresume%3Dapply'
        : verificationUrl
    }
  });
}

// 兼容旧导入名称；语义已经变为只处理显式 pending risk 的自适应门禁。
const guestVerificationGate = adaptiveVerificationGate;

/** 创建容量受控的固定窗口限流中间件。 */
function createRateLimiter(name, windowMs, maxRequests) {
  return (req, res, next) => {
    const now = Date.now();
    const ip = getClientIp(req) || 'unknown';
    const key = `${name}:${ip}`;
    const record = endpointRateLimitCache.get(key);

    if (!record || now >= record.resetAt) {
      endpointRateLimitCache.set(key, { count: 1, resetAt: now + windowMs }, { ttl: windowMs });
      return next();
    }

    if (record.count >= maxRequests) {
      const retryAfter = Math.max(1, Math.ceil((record.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ code: 429, msg: `请求过于频繁，请 ${retryAfter} 秒后再试`, data: null });
    }

    endpointRateLimitCache.set(
      key,
      { count: record.count + 1, resetAt: record.resetAt },
      { ttl: Math.max(1, record.resetAt - now) }
    );
    return next();
  };
}

/** 返回 true 表示同一站点/IP 仍在 60 秒冷却窗口内。 */
function isPartnerVisitRateLimited(partnerId, ip) {
  const key = `${partnerId}_${ip}`;
  if (visitRateLimitCache.has(key)) return true;
  visitRateLimitCache.set(key, Date.now());
  return false;
}

/** 返回 true 表示当前安全事件应发送告警，并同时写入冷却记录。 */
function shouldSendSecurityAlert(reason, ip, targetId = '—') {
  const key = `${reason}:${ip}:${targetId}`;
  if (securityAlertCache.has(key)) return false;
  securityAlertCache.set(key, Date.now());
  return true;
}

function storeVerificationNonce(nonce, record) {
  const ttl = Math.max(1, Number(record?.expiresAt || 0) - Date.now());
  verificationNonces.set(nonce, record, { ttl });
}

function getVerificationNonce(nonce) {
  return verificationNonces.get(nonce);
}

function consumeVerificationNonce(nonce) {
  verificationNonces.delete(nonce);
}

module.exports = {
  RATE_LIMIT_WINDOW_MS,
  VERIFY_NONCE_TTL_MS,
  VERIFY_COOKIE_TTL_MS,
  GUEST_VERIFY_COOKIE,
  GUEST_VISITOR_COOKIE,
  createRateLimiter,
  observeRequestRisk,
  applyRiskProtection,
  outboundRiskProtection,
  adaptiveVerificationGate,
  guestVerificationGate,
  ensureVisitorIdentity,
  hasFreshGuestVerification,
  storePendingTrafficReferer,
  readPendingTrafficReferer,
  clearPendingTrafficReferer,
  storePendingTrafficSource,
  readPendingTrafficSource,
  clearPendingTrafficSource,
  getCookie,
  isPartnerVisitRateLimited,
  shouldSendSecurityAlert,
  storeVerificationNonce,
  getVerificationNonce,
  consumeVerificationNonce
};
