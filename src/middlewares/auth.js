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
  res.cookie(ADMIN_CSRF_COOKIE, String(payload.csrf || ''), { ...options, httpOnly: false });
}

function clearAdminSessionCookies(res) {
  const options = { secure: IS_PRODUCTION, sameSite: 'strict', path: '/' };
  res.clearCookie(ADMIN_SESSION_COOKIE, options);
  res.clearCookie(ADMIN_CSRF_COOKIE, options);
}

/** JWT 管理身份校验：浏览器优先使用 HttpOnly Cookie，保留短暂 Bearer 仅供统一后台交换。 */
async function requireAdmin(req, res, next) {
  const bearer = req.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  const token = readCookie(req, ADMIN_SESSION_COOKIE) || bearer;
  if (!token) {
    return res.status(401).json({ code: 401, msg: '需要管理员令牌', data: null });
  }

  let payload;
  try {
    payload = jwt.verify(token, ADMIN_JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return res.status(401).json({ code: 401, msg: '登录已过期或令牌无效', data: null });
  }

  if (payload?.role !== 'admin' || payload?.type !== 'admin') {
    return res.status(403).json({ code: 403, msg: '令牌没有管理员权限', data: null });
  }
  try {
    const admin = await SystemModel.getAdminSessionById(payload.id);
    if (!admin || Number(admin.session_version || 0) !== Number(payload.sv)) {
      return res.status(401).json({ code: 401, msg: '登录会话已失效，请重新登录', data: null });
    }
  } catch (error) {
    console.error('读取管理员会话版本失败：', error);
    return res.status(503).json({ code: 503, msg: '管理员会话暂不可用，请稍后重试', data: null });
  }
  if (CONTROL_CENTER_ENABLED && payload?.source !== 'control_center') {
    return res.status(401).json({ code: 401, msg: '请从总后台重新进入本站后台', data: null });
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
  clearAdminSessionCookies
};
