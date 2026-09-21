'use strict';

const crypto = require('crypto');
const { LRUCache } = require('lru-cache');

const MAX_SKEW_MS = 60_000;
const NONCE_TTL_MS = 5 * 60_000;
const usedNonces = new LRUCache({ max: 200_000, ttl: NONCE_TTL_MS });

function sha256(body) {
  return crypto.createHash('sha256').update(body || Buffer.alloc(0)).digest('hex');
}

function canonicalRequest({ method, pathAndQuery, timestamp, nonce, body }) {
  return [
    String(method || '').toUpperCase(),
    String(pathAndQuery || ''),
    String(timestamp || ''),
    String(nonce || ''),
    sha256(body)
  ].join('\n');
}

function sign(secret, request) {
  return crypto.createHmac('sha256', secret)
    .update(canonicalRequest(request))
    .digest('hex');
}

function safeEqualHex(left, right) {
  if (!/^[a-f0-9]{64}$/i.test(left) || !/^[a-f0-9]{64}$/i.test(right)) return false;
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function authenticate({ clientId, secret, method, pathAndQuery, timestamp, nonce, signature, body, now = Date.now() }) {
  const numericTimestamp = Number(timestamp);
  if (!clientId || !secret || !nonce || nonce.length > 128) return { ok: false, reason: 'missing_credentials' };
  if (!Number.isFinite(numericTimestamp) || Math.abs(now - numericTimestamp) > MAX_SKEW_MS) {
    return { ok: false, reason: 'timestamp_out_of_range' };
  }
  const nonceKey = `${clientId}:${nonce}`;
  if (usedNonces.has(nonceKey)) return { ok: false, reason: 'nonce_replay' };
  const expected = sign(secret, { method, pathAndQuery, timestamp, nonce, body });
  if (!safeEqualHex(expected, String(signature || ''))) return { ok: false, reason: 'invalid_signature' };
  usedNonces.set(nonceKey, true);
  return { ok: true };
}

function clearReplayState() {
  usedNonces.clear();
}

module.exports = {
  MAX_SKEW_MS,
  NONCE_TTL_MS,
  sha256,
  canonicalRequest,
  sign,
  authenticate,
  clearReplayState
};
