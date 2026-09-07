'use strict';

const jwt = require('jsonwebtoken');
const { LRUCache } = require('lru-cache');
const { GUEST_JWT_SECRET, IS_PRODUCTION, TRAFFIC_DEBUG } = require('../config/env');
const { getClientIp, parseHostname } = require('../utils/network');

const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const SECURITY_ALERT_COOLDOWN_MS = 5 * 60 * 1000;
const GUEST_VERIFY_COOKIE = 'guest_verify_token';
const PENDING_TRAFFIC_REFERER_COOKIE = 'pending_traffic_referer';
const VERIFY_NONCE_TTL_MS = 60 * 1000;
const VERIFY_COOKIE_TTL_MS = 12 * 60 * 60 * 1000;
const PENDING_TRAFFIC_REFERER_TTL_SECONDS = 5 * 60;

// 容量受控的内存状态：LRU 自动淘汰，避免恶意 IP/端点扫描无限占用内存。
const visitRateLimitCache = new LRUCache({ max: 100000, ttl: RATE_LIMIT_WINDOW_MS });
const securityAlertCache = new LRUCache({ max: 100000, ttl: SECURITY_ALERT_COOLDOWN_MS });
const endpointRateLimitCache = new LRUCache({ max: 100000, ttl: 60 * 60 * 1000 });
const verificationNonces = new LRUCache({ max: 50000, ttl: VERIFY_NONCE_TTL_MS });

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

function hasGuestVerification(req) {
  try {
    const payload = jwt.verify(readCookie(req, GUEST_VERIFY_COOKIE), GUEST_JWT_SECRET, { algorithms: ['HS256'] });
    return payload?.scope === 'guest-verified'
      && payload?.role === 'guest'
      && payload?.type === 'guest-verification';
  } catch {
    return false;
  }
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

/** 未验证的公开请求转入滑块页，并保存验证回跳后仍需恢复的外部 Referer。 */
function guestVerificationGate(req, res, next) {
  if (isVerificationExempt(req) || hasGuestVerification(req)) return next();

  if (req.method === 'GET' && req.path === '/' && !req.pendingTrafficRefererStored) {
    storePendingTrafficReferer(req, res);
  }

  const target = encodeURIComponent(req.originalUrl || '/');
  return res.redirect(302, `/verify.html?target=${target}`);
}

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
  createRateLimiter,
  guestVerificationGate,
  storePendingTrafficReferer,
  readPendingTrafficReferer,
  clearPendingTrafficReferer,
  getCookie,
  isPartnerVisitRateLimited,
  shouldSendSecurityAlert,
  storeVerificationNonce,
  getVerificationNonce,
  consumeVerificationNonce
};
