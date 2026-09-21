'use strict';

const crypto = require('crypto');
const { LRUCache } = require('lru-cache');
const { ADMIN_TOKEN, IS_PRODUCTION } = require('../config/env');

const COOKIE_NAME = 'risk_admin_session';
const SESSION_TTL_MS = 8 * 60 * 60_000;
const sessions = new LRUCache({ max: 1000, ttl: SESSION_TTL_MS });

function parseCookies(header = '') {
  const result = {};
  for (const item of String(header).split(';')) {
    const separator = item.indexOf('=');
    if (separator < 1) continue;
    const name = item.slice(0, separator).trim();
    try { result[name] = decodeURIComponent(item.slice(separator + 1).trim()); }
    catch { result[name] = ''; }
  }
  return result;
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left || ''));
  const rightBuffer = Buffer.from(String(right || ''));
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function createSession(token) {
  if (ADMIN_TOKEN.length < 32 || !safeEqual(token, ADMIN_TOKEN)) return null;
  const sessionId = crypto.randomBytes(32).toString('base64url');
  const csrfToken = crypto.randomBytes(24).toString('base64url');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(sessionId, { csrfToken, expiresAt });
  return { sessionId, csrfToken, expiresAt };
}

function sessionFromRequest(req) {
  const sessionId = parseCookies(req.get('cookie'))[COOKIE_NAME];
  const session = sessionId ? sessions.get(sessionId) : null;
  if (!session || session.expiresAt <= Date.now()) return null;
  return { sessionId, ...session };
}

function cookieOptions() {
  return {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    maxAge: SESSION_TTL_MS,
    path: '/admin'
  };
}

function destroySession(req) {
  const session = sessionFromRequest(req);
  if (session) sessions.delete(session.sessionId);
}

function requireAdmin(req, res, next) {
  const session = sessionFromRequest(req);
  if (!session) return res.status(401).json({ code: 401, message: 'Unauthorized' });
  req.riskAdmin = session;
  return next();
}

function requireCsrf(req, res, next) {
  const token = String(req.get('X-CSRF-Token') || '');
  if (!req.riskAdmin || !safeEqual(token, req.riskAdmin.csrfToken)) {
    return res.status(403).json({ code: 403, message: 'Invalid CSRF token' });
  }
  return next();
}

function resetForTests() { sessions.clear(); }

module.exports = {
  COOKIE_NAME,
  SESSION_TTL_MS,
  createSession,
  sessionFromRequest,
  cookieOptions,
  destroySession,
  requireAdmin,
  requireCsrf,
  resetForTests
};
