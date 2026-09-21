'use strict';

const crypto = require('crypto');
const { LRUCache } = require('lru-cache');
const { ADMIN_USERNAME, ADMIN_PASSWORD_HASH, IS_PRODUCTION } = require('../config/env');

const COOKIE_NAME = 'risk_admin_session';
const SESSION_TTL_MS = 8 * 60 * 60_000;
const sessions = new LRUCache({ max: 1000, ttl: SESSION_TTL_MS });
const failedLogins = new LRUCache({ max: 10_000, ttl: 15 * 60_000 });

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

function derivePassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(String(password || ''), salt, 64, (error, result) => {
      if (error) reject(error);
      else resolve(result);
    });
  });
}

async function validCredentials(username, password) {
  const [algorithm, salt, expectedHex] = ADMIN_PASSWORD_HASH.split('$');
  if (algorithm !== 'scrypt' || !salt || !/^[a-f0-9]{128}$/i.test(expectedHex || '')) return false;
  const actual = await derivePassword(password, salt);
  const expected = Buffer.from(expectedHex, 'hex');
  return safeEqual(username, ADMIN_USERNAME)
    && actual.length === expected.length
    && crypto.timingSafeEqual(actual, expected);
}

async function createSession(username, password, source = 'unknown') {
  const attemptKey = String(source || 'unknown').slice(0, 128);
  if ((failedLogins.get(attemptKey) || 0) >= 5) return null;
  if (!await validCredentials(username, password)) {
    failedLogins.set(attemptKey, (failedLogins.get(attemptKey) || 0) + 1);
    return null;
  }
  failedLogins.delete(attemptKey);
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

function resetForTests() {
  sessions.clear();
  failedLogins.clear();
}

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
