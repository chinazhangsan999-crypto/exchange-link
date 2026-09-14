'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {
  ADMIN_JWT_SECRET,
  CONTROL_CENTER_ENABLED,
  IS_PRODUCTION,
  ADMIN_SESSION_TTL_MS,
  ADMIN_SESSION_COOKIE,
  ADMIN_CSRF_COOKIE
} = require('../config/env');
const SystemModel = require('../models/SystemModel');

function readCookie(req, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp(`(?:^|;\\s*)${escaped}=([^;]*)`).exec(String(req.headers.cookie || ''));
  return match ? decodeURIComponent(match[1]) : '';
}

function issueAdminToken(admin, extra = {}) {
  return jwt.sign({
    id: admin.id,
    username: admin.username,
    role: 'admin',
    type: 'admin',
    sv: Number(admin.session_version || 0),
    csrf: crypto.randomBytes(24).toString('base64url'),
    ...extra
  }, ADMIN_JWT_SECRET, { expiresIn: '8h', algorithm: 'HS256' });
}

function setAdminSessionCookies(res, token) {
  const payload = jwt.decode(token) || {};
  const options = { maxAge: ADMIN_SESSION_TTL_MS, secure: IS_PRODUCTION, sameSite: 'strict', path: '/' };
  res.cookie(ADMIN_SESSION_COOKIE, token, { ...options, httpOnly: true });
  return String(payload.csrf || '');
}

function setAdminCsrfCookie(res, csrfToken) {
  const options = { maxAge: ADMIN_SESSION_TTL_MS, secure: IS_PRODUCTION, sameSite: 'strict', path: '/' };
  res.cookie(ADMIN_CSRF_COOKIE, String(csrfToken || ''), { ...options, httpOnly: false });
}

function clearAdminSessionCookies(res) {
  const options = { secure: IS_PRODUCTION, sameSite: 'strict', path: '/' };
  res.clearCookie(ADMIN_SESSION_COOKIE, options);
  res.clearCookie(ADMIN_CSRF_COOKIE, options);
}

function rejectAdminSession(req, res, status, message, reason) {
  // 仅记录已通过后台边缘验签的请求，不记录 Token、Cookie 或原始 Authorization，
  // 这样能诊断 SSO 会话问题，同时不会把凭证写入日志。
  if (req.trustedFrontendOrigin) {
    console.warn(`[后台会话] 拒绝请求 path=${req.path} reason=${reason} origin=${req.trustedFrontendOrigin}`);
  }
  return res.status(status).json({ code: status, msg: message, data: null });
}

/** JWT 管理身份校验：浏览器优先使用 HttpOnly Cookie，保留短暂 Bearer 仅供统一后台交换。 */
async function requireAdmin(req, res, next) {
  const bearer = req.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  const token = readCookie(req, ADMIN_SESSION_COOKIE) || bearer;
  if (!token) {
    return rejectAdminSession(req, res, 401, '需要管理员令牌', 'missing_session');
  }

  let payload;
  try {
    payload = jwt.verify(token, ADMIN_JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return rejectAdminSession(req, res, 401, '登录已过期或令牌无效', 'invalid_token');
  }

  if (payload?.role !== 'admin' || payload?.type !== 'admin') {
    return rejectAdminSession(req, res, 403, '令牌没有管理员权限', 'invalid_role');
  }
  try {
    const admin = await SystemModel.getAdminSessionById(payload.id);
    if (!admin || Number(admin.session_version || 0) !== Number(payload.sv)) {
      return rejectAdminSession(req, res, 401, '登录会话已失效，请重新登录', 'session_version_mismatch');
    }
  } catch (error) {
    console.error('读取管理员会话版本失败：', error);
    return res.status(503).json({ code: 503, msg: '管理员会话暂不可用，请稍后重试', data: null });
  }
  if (CONTROL_CENTER_ENABLED && payload?.source !== 'control_center') {
    return rejectAdminSession(req, res, 401, '请从总后台重新进入本站后台', 'wrong_session_source');
  }

  req.admin = payload;
  req.adminToken = token;
  return next();
}

function requireAdminCsrf(req, res, next) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const supplied = String(req.get('x-csrf-token') || '');
  const cookie = readCookie(req, ADMIN_CSRF_COOKIE);
  const suppliedBuffer = Buffer.from(supplied);
  const cookieBuffer = Buffer.from(cookie);
  const claimBuffer = Buffer.from(String(req.admin?.csrf || ''));
  if (!supplied || !cookie || !req.admin?.csrf
    || suppliedBuffer.length !== cookieBuffer.length
    || suppliedBuffer.length !== claimBuffer.length
    || !crypto.timingSafeEqual(suppliedBuffer, cookieBuffer)
    || !crypto.timingSafeEqual(suppliedBuffer, claimBuffer)) {
    return res.status(403).json({ code: 403, msg: 'CSRF 校验失败，请刷新后台后重试', data: null });
  }
  return next();
}

module.exports = {
  requireAdmin,
  requireAdminCsrf,
  issueAdminToken,
  setAdminSessionCookies,
  setAdminCsrfCookie,
  clearAdminSessionCookies
};
