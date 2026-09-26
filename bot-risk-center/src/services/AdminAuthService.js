'use strict';

const crypto = require('crypto');
const { LRUCache } = require('lru-cache');
const { ADMIN_USERNAME, ADMIN_PASSWORD_HASH, IS_PRODUCTION } = require('../config/env');
const StorageService = require('./StorageService');

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

function sessionHash(sessionId) {
  return crypto.createHash('sha256').update(String(sessionId || '')).digest('hex');
}

function derivePassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(String(password || ''), salt, 64, (error, result) => {
      if (error) reject(error); else resolve(result);
    });
  });
}

async function passwordHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await derivePassword(password, salt);
  return `scrypt$${salt}$${hash.toString('hex')}`;
}

async function credential() {
  return await StorageService.getAdminCredential() || {
    username: ADMIN_USERNAME, passwordHash: ADMIN_PASSWORD_HASH, credentialVersion: 1
  };
}

async function validCredentials(username, password) {
  const current = await credential();
  const [algorithm, salt, expectedHex] = String(current.passwordHash || '').split('$');
  if (algorithm !== 'scrypt' || !salt || !/^[a-f0-9]{128}$/i.test(expectedHex || '')) return false;
  const actual = await derivePassword(password, salt);
  const expected = Buffer.from(expectedHex, 'hex');
  return safeEqual(username, current.username)
    && actual.length === expected.length
    && crypto.timingSafeEqual(actual, expected);
}

function requestContext(input = {}) {
  if (typeof input === 'string') return { sourceIp: input, userAgent: '' };
  return {
    sourceIp: String(input.sourceIp || input.ip || 'unknown').slice(0, 120),
    userAgent: String(input.userAgent || '').slice(0, 500)
  };
}

async function createSession(username, password, source = {}) {
  const context = requestContext(source);
  const attemptKey = context.sourceIp;
  if ((failedLogins.get(attemptKey) || 0) >= 5) {
    await StorageService.recordAdminAudit('anonymous', 'admin_login_blocked', String(username || ''), {}, context);
    return null;
  }
  if (!await validCredentials(username, password)) {
    failedLogins.set(attemptKey, (failedLogins.get(attemptKey) || 0) + 1);
    await StorageService.recordAdminAudit('anonymous', 'admin_login_failed', String(username || ''), {
      failedCount: failedLogins.get(attemptKey)
    }, context);
    return null;
  }
  failedLogins.delete(attemptKey);
  const current = await credential();
  const sessionId = crypto.randomBytes(32).toString('base64url');
  const csrfToken = crypto.randomBytes(24).toString('base64url');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const record = { username: current.username, csrfToken, expiresAt, ...context };
  sessions.set(sessionId, record);
  await StorageService.createAdminSessionRecord({
    sessionHash: sessionHash(sessionId), username: current.username, csrfToken, expiresAt,
    credentialVersion: current.credentialVersion, ...context
  });
  await StorageService.recordAdminAudit(current.username, 'admin_login_success', 'admin-session', {}, context);
  return { sessionId, ...record };
}

async function sessionFromRequest(req) {
  const sessionId = parseCookies(req.get('cookie'))[COOKIE_NAME];
  if (!sessionId) return null;
  const session = StorageService.hasDatabase()
    ? await StorageService.getAdminSessionRecord(sessionHash(sessionId))
    : sessions.get(sessionId);
  if (!session || session.expiresAt <= Date.now()) return null;
  return { sessionId, sessionHash: sessionHash(sessionId), ...session };
}

function cookieOptions() {
  return { httpOnly: true, secure: IS_PRODUCTION, sameSite: 'strict', maxAge: SESSION_TTL_MS, path: '/admin' };
}

async function destroySession(req, reason = 'logout') {
  const session = await sessionFromRequest(req);
  if (!session) return false;
  sessions.delete(session.sessionId);
  await StorageService.revokeAdminSessionByHash(session.sessionHash, reason);
  await StorageService.recordAdminAudit(session.username, 'admin_logout', 'admin-session', {}, {
    sourceIp: session.sourceIp, userAgent: session.userAgent
  });
  return true;
}

async function changeCredentials(session, currentPassword, nextUsername, nextPassword, context = {}) {
  if (!session || !await validCredentials(session.username, currentPassword)) return null;
  const username = String(nextUsername || '').trim();
  const password = String(nextPassword || '');
  if (!/^[A-Za-z0-9_.@-]{3,64}$/.test(username) || password.length < 8 || password.length > 256) {
    throw new Error('新账号需为 3–64 位，新密码需为 8–256 位');
  }
  const result = await StorageService.updateAdminCredential({ username, passwordHash: await passwordHash(password) }, {
    actor: session.username, ...requestContext(context)
  });
  sessions.clear();
  return result || { username, credentialVersion: 2, passwordChangedAt: new Date().toISOString() };
}

async function listSessions(current) {
  const rows = await StorageService.listAdminSessions(current?.sessionHash || '');
  if (rows.length) return rows;
  return current ? [{ id: 0, username: current.username, sourceIp: current.sourceIp || '', userAgent: current.userAgent || '',
    createdAt: null, lastSeenAt: null, expiresAt: new Date(current.expiresAt).toISOString(), current: true }] : [];
}

async function revokeSession(current, id, context = {}) {
  const result = await StorageService.revokeAdminSession(Number(id), current.sessionHash, current.username, requestContext(context));
  if (result?.current) sessions.delete(current.sessionId);
  return result;
}

async function revokeOtherSessions(current, context = {}) {
  return StorageService.revokeOtherAdminSessions(current.sessionHash, current.username, requestContext(context));
}

async function revokeAllSessions(current, context = {}) {
  const count = await StorageService.revokeAllAdminSessions(current.username, requestContext(context));
  sessions.clear();
  return count;
}

async function requireAdmin(req, res, next) {
  const session = await sessionFromRequest(req);
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

function resetForTests() { sessions.clear(); failedLogins.clear(); }

module.exports = {
  COOKIE_NAME, SESSION_TTL_MS, createSession, sessionFromRequest, cookieOptions, destroySession,
  changeCredentials, listSessions, revokeSession, revokeOtherSessions, revokeAllSessions,
  requireAdmin, requireCsrf, resetForTests, passwordHash, validCredentials
};
