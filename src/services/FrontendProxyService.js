'use strict';

const crypto = require('crypto');
const net = require('net');
const { LRUCache } = require('lru-cache');
const {
  IS_PRODUCTION,
  FRONTEND_PROXY_SECRET,
  FRONTEND_PROXY_MAX_SKEW_MS
} = require('../config/env');
const FrontendOriginModel = require('../models/FrontendOriginModel');

const ORIGIN_CACHE_TTL_MS = 30 * 1000;
const usedNonces = new LRUCache({ max: 100000, ttl: FRONTEND_PROXY_MAX_SKEW_MS * 2 });
let originCache = { expiresAt: 0, values: new Set() };

function normalizeFrontendOrigin(value) {
  try {
    const parsed = new URL(String(value || '').trim());
    const localDevelopment = !IS_PRODUCTION
      && parsed.protocol === 'http:'
      && ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
    if (parsed.protocol !== 'https:' && !localDevelopment) return '';
    if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
    return parsed.origin.toLowerCase();
  } catch {
    return '';
  }
}

async function getAllowedOrigins() {
  if (originCache.expiresAt > Date.now()) return originCache.values;
  const rows = await FrontendOriginModel.listEnabledOrigins();
  const next = new Set(rows.map(row => normalizeFrontendOrigin(row.origin)).filter(Boolean));
  originCache = { expiresAt: Date.now() + ORIGIN_CACHE_TTL_MS, values: next };
  return next;
}

function clearAllowedOriginCache() {
  originCache = { expiresAt: 0, values: new Set() };
}

function bodyHash(rawBody) {
  const source = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody || '');
  return crypto.createHash('sha256').update(source).digest('hex');
}

function canonicalProxyPayload({ timestamp, nonce, method, path, origin, clientIp, confirmedBot, rawBody }) {
  return [
    String(timestamp || ''),
    String(nonce || ''),
    String(method || 'GET').toUpperCase(),
    String(path || '/'),
    String(origin || ''),
    String(clientIp || ''),
    confirmedBot === '1' ? '1' : '0',
    bodyHash(rawBody)
  ].join('\n');
}

function canonicalProxyPayloadLegacy({ timestamp, nonce, method, path, origin, clientIp, rawBody }) {
  return [String(timestamp || ''), String(nonce || ''), String(method || 'GET').toUpperCase(),
    String(path || '/'), String(origin || ''), String(clientIp || ''), bodyHash(rawBody)].join('\n');
}

function signProxyRequest(input, secret = FRONTEND_PROXY_SECRET) {
  if (!secret) throw new Error('前台代理签名密钥尚未配置');
  return crypto.createHmac('sha256', secret)
    .update(canonicalProxyPayload(input))
    .digest('hex');
}

function safeEqualHex(left, right) {
  const a = Buffer.from(String(left || ''), 'hex');
  const b = Buffer.from(String(right || ''), 'hex');
  return a.length === 32 && b.length === 32 && crypto.timingSafeEqual(a, b);
}

async function verifyProxyRequest(req) {
  const origin = normalizeFrontendOrigin(req.get('x-frontend-origin'));
  const clientIp = String(req.get('x-verified-client-ip') || '').trim();
  const timestamp = Number(req.get('x-proxy-timestamp'));
  const nonce = String(req.get('x-proxy-nonce') || '').trim();
  const signature = String(req.get('x-proxy-signature') || '').trim().toLowerCase();
  const confirmedBotHeader = req.get('x-edge-confirmed-bot');
  const confirmedBot = confirmedBotHeader === '1' ? '1' : '0';

  if (!FRONTEND_PROXY_SECRET) return { ok: false, reason: 'proxy_disabled' };
  if (!origin || !net.isIP(clientIp)) return { ok: false, reason: 'invalid_context' };
  if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > FRONTEND_PROXY_MAX_SKEW_MS) {
    return { ok: false, reason: 'expired' };
  }
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) return { ok: false, reason: 'invalid_nonce' };
  const nonceKey = `${origin}:${nonce}`;

  const allowedOrigins = await getAllowedOrigins();
  if (!allowedOrigins.has(origin)) return { ok: false, reason: 'origin_denied' };
  const expected = signProxyRequest({
    timestamp,
    nonce,
    method: req.method,
    path: req.originalUrl || req.url,
    origin,
    clientIp,
    confirmedBot,
    rawBody: req.rawBody
  });
  if (!safeEqualHex(signature, expected)) {
    if (confirmedBotHeader !== undefined) return { ok: false, reason: 'bad_signature' };
    const legacy = crypto.createHmac('sha256', FRONTEND_PROXY_SECRET)
      .update(canonicalProxyPayloadLegacy({ timestamp, nonce, method: req.method, path: req.originalUrl || req.url, origin, clientIp, rawBody: req.rawBody }))
      .digest('hex');
    if (!safeEqualHex(signature, legacy)) return { ok: false, reason: 'bad_signature' };
  }

  // 放在最后一次 await 之后同步检查并占位，避免两个同 Nonce 请求并发穿透。
  if (usedNonces.has(nonceKey)) return { ok: false, reason: 'replayed' };
  usedNonces.set(nonceKey, true);
  return { ok: true, origin, clientIp, confirmedBot: confirmedBot === '1' };
}

module.exports = {
  normalizeFrontendOrigin,
  getAllowedOrigins,
  clearAllowedOriginCache,
  canonicalProxyPayload,
  signProxyRequest,
  verifyProxyRequest
};
