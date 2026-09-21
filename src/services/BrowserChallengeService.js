'use strict';

const crypto = require('crypto');
const { LRUCache } = require('lru-cache');
const {
  BOT_GATE_MODE,
  EDGE_ACCESS_SECRET,
  BROWSER_ACCESS_TTL_MS
} = require('../config/env');

const COOKIE_NAME = 'browser_access_token';
const CHALLENGE_TTL_MS = 30_000;
const challenges = new LRUCache({ max: 100000, ttl: CHALLENGE_TTL_MS });

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function uaHash(userAgent) {
  return crypto.createHash('sha256').update(String(userAgent || '').slice(0, 600)).digest('hex').slice(0, 24);
}

function leadingZeroBits(buffer) {
  let bits = 0;
  for (const byte of buffer) {
    if (byte === 0) { bits += 8; continue; }
    for (let mask = 0x80; mask > 0 && (byte & mask) === 0; mask >>= 1) bits += 1;
    break;
  }
  return bits;
}

function issue(visitorId, decision = null, now = Date.now()) {
  const challengeId = crypto.randomUUID();
  const salt = crypto.randomBytes(18).toString('base64url');
  const requested = decision?.decision === 'strong_challenge' ? 16
    : decision?.decision === 'silent_challenge' ? 12 : 10;
  const difficultyBits = Math.max(8, Math.min(18, requested));
  challenges.set(challengeId, {
    visitorId,
    salt,
    difficultyBits,
    issuedAt: now,
    expiresAt: now + CHALLENGE_TTL_MS
  });
  return { challengeId, salt, difficultyBits, expiresAt: now + CHALLENGE_TTL_MS };
}

function verifyProof(visitorId, payload = {}, now = Date.now()) {
  const challengeId = String(payload.challengeId || '');
  const solution = Number(payload.solution);
  const record = challenges.get(challengeId);
  if (!record || record.visitorId !== visitorId || record.expiresAt <= now
    || !Number.isSafeInteger(solution) || solution < 0) return { ok: false, reason: 'invalid-proof' };
  challenges.delete(challengeId);
  const digest = crypto.createHash('sha256')
    .update(`${challengeId}:${record.salt}:${solution}`)
    .digest();
  if (leadingZeroBits(digest) < record.difficultyBits) return { ok: false, reason: 'invalid-proof' };
  const elapsed = now - record.issuedAt;
  if (elapsed < 0 || elapsed > CHALLENGE_TTL_MS) return { ok: false, reason: 'invalid-elapsed' };
  return { ok: true, elapsed, difficultyBits: record.difficultyBits };
}

function signPayload(encodedPayload) {
  return crypto.createHmac('sha256', EDGE_ACCESS_SECRET).update(encodedPayload).digest('hex');
}

function issueAccessToken(visitorId, userAgent, level = 'browser', now = Date.now()) {
  if (EDGE_ACCESS_SECRET.length < 32) throw new Error('浏览器通行证签名密钥未配置');
  const payload = {
    type: 'browser-access',
    visitorId,
    ua: uaHash(userAgent),
    level,
    iat: now,
    exp: now + BROWSER_ACCESS_TTL_MS,
    policy: 'v1'
  };
  const encoded = base64url(JSON.stringify(payload));
  return `${encoded}.${signPayload(encoded)}`;
}

function verifyAccessToken(token, visitorId, userAgent, now = Date.now()) {
  if (!token || EDGE_ACCESS_SECRET.length < 32) return null;
  const dot = String(token).lastIndexOf('.');
  if (dot < 1) return null;
  const encoded = String(token).slice(0, dot);
  const signature = String(token).slice(dot + 1);
  const expected = signPayload(encoded);
  if (signature.length !== expected.length
    || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (payload.type !== 'browser-access' || payload.visitorId !== visitorId
      || payload.ua !== uaHash(userAgent) || Number(payload.exp) <= now) return null;
    return payload;
  } catch {
    return null;
  }
}

function isEnforced() { return BOT_GATE_MODE === 'enforce'; }
function resetForTests() { challenges.clear(); }

module.exports = {
  COOKIE_NAME,
  issue,
  verifyProof,
  issueAccessToken,
  verifyAccessToken,
  isEnforced,
  resetForTests
};
