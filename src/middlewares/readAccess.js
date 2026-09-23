'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { LRUCache } = require('lru-cache');
const { createClient } = require('redis');
const { GUEST_JWT_SECRET, IS_PRODUCTION } = require('../config/env');
const { ensureVisitorIdentity } = require('./rateLimit');
const VisitorRiskService = require('../services/VisitorRiskService');
const BotRiskClient = require('../services/BotRiskClient');

const READ_TOKEN_TTL_SECONDS = 60;
const READ_TOKEN_MAX_USES = 16;
const READ_ACCESS_SCOPES = Object.freeze([
  'links:list',
  'links:detail',
  'showcase:read'
]);

// 只保存短期 jti 使用状态，容量满后由 LRU 自动淘汰，避免扫描造成内存无界增长。
const issuedReadTokens = new LRUCache({
  max: 100000,
  ttl: READ_TOKEN_TTL_SECONDS * 1000
});
let redisClient = null;
let redisConnectPromise = null;

async function getReadTokenRedis() {
  const url = String(process.env.READ_ACCESS_REDIS_URL || process.env.REDIS_URL || '').trim();
  if (!url) return null;
  if (!redisClient) {
    redisClient = createClient({ url, socket: { connectTimeout: 300, reconnectStrategy: false } });
    redisClient.on('error', error => console.warn('读取凭证 Redis 暂不可用，已回退单进程计数：', error.message));
    redisConnectPromise = redisClient.connect().catch(() => null);
  }
  await redisConnectPromise;
  return redisClient?.isReady ? redisClient : null;
}

function sendReadAccessRequired(res, msg = '读取凭证缺失或已过期') {
  res.set('Cache-Control', 'private, no-store');
  return res.status(428).json({
    code: 428,
    msg: IS_PRODUCTION ? '请求无法处理' : msg,
    data: null
  });
}

function sendReadAccessDenied(res, msg) {
  return res.status(403).json({
    code: 403,
    msg: IS_PRODUCTION ? '请求无法处理' : msg,
    data: null
  });
}

async function issueReadAccessToken(req, res) {
  const visitorId = ensureVisitorIdentity(req, res);
  const origin = String(req.trustedFrontendOrigin || `${req.protocol}://${req.get('host')}`).toLowerCase();
  const jti = crypto.randomUUID();
  const issuedAt = Date.now();
  const expiresAt = issuedAt + READ_TOKEN_TTL_SECONDS * 1000;
  const token = jwt.sign(
    {
      type: 'read-access',
      role: 'guest',
      visitorId,
      origin,
      scope: READ_ACCESS_SCOPES,
      jti
    },
    GUEST_JWT_SECRET,
    { expiresIn: READ_TOKEN_TTL_SECONDS, algorithm: 'HS256' }
  );

  issuedReadTokens.set(jti, { visitorId, origin, uses: 0, expiresAt });
  const redis = await getReadTokenRedis();
  if (redis) await redis.hSet(`read-token:${jti}`, { visitorId, origin, uses: '0' }).then(() => redis.expire(`read-token:${jti}`, READ_TOKEN_TTL_SECONDS));
  res.set('Cache-Control', 'private, no-store');
  return { token, expiresIn: READ_TOKEN_TTL_SECONDS, expiresAt };
}

function requireReadAccess(requiredScope) {
  if (!READ_ACCESS_SCOPES.includes(requiredScope)) {
    throw new Error(`未知的读取凭证 scope: ${requiredScope}`);
  }

  return async (req, res, next) => {
    res.set('Cache-Control', 'private, no-store');
    const token = String(req.get('X-Read-Token') || '').trim();
    if (!token || token.length > 4096) return sendReadAccessRequired(res);

    let payload;
    try {
      payload = jwt.verify(token, GUEST_JWT_SECRET, { algorithms: ['HS256'] });
    } catch (error) {
      if (error?.name === 'TokenExpiredError') return sendReadAccessRequired(res);
      return sendReadAccessDenied(res, '读取凭证无效');
    }

    const visitorId = ensureVisitorIdentity(req, res);
    const origin = String(req.trustedFrontendOrigin || `${req.protocol}://${req.get('host')}`).toLowerCase();
    const centralDecision = BotRiskClient.getDecision(visitorId);
    if (centralDecision?.enforce && centralDecision.decision === 'deny') {
      return sendReadAccessDenied(res, '当前读取会话已被拒绝');
    }
    if (centralDecision?.enforce
      && ['silent_challenge', 'strong_challenge'].includes(centralDecision.decision)
      && !BotRiskClient.hasChallengeBypass(visitorId)) {
      return sendReadAccessRequired(res, '当前读取会话需要重新验证');
    }
    const restriction = VisitorRiskService.getReadRestriction(visitorId);
    if (restriction) {
      res.set('Retry-After', String(restriction.retryAfter));
      return res.status(429).json({
        code: 429,
        msg: IS_PRODUCTION ? '请求无法处理' : '当前读取会话请求异常，请稍后重试',
        data: null
      });
    }
    const scopes = Array.isArray(payload?.scope) ? payload.scope : [];
    if (payload?.type !== 'read-access'
      || payload?.role !== 'guest'
      || payload?.visitorId !== visitorId
      || payload?.origin !== origin
      || typeof payload?.jti !== 'string') {
      BotRiskClient.enqueue(visitorId, 'token_replay', { reason: 'visitor_or_origin_mismatch', scope: requiredScope });
      return sendReadAccessDenied(res, '读取凭证与当前访客或接口不匹配');
    }
    if (!scopes.includes(requiredScope)) {
      BotRiskClient.enqueue(visitorId, 'token_replay', { reason: 'scope_mismatch', scope: requiredScope });
      return sendReadAccessDenied(res, '读取凭证不允许访问当前接口');
    }

    let record = issuedReadTokens.get(payload.jti);
    const redis = await getReadTokenRedis();
    if (redis) {
      const result = await redis.eval(`local v=redis.call('HGET',KEYS[1],'visitorId'); if not v then return {-1,0} end; local o=redis.call('HGET',KEYS[1],'origin'); if v~=ARGV[1] or o~=ARGV[2] then return {-2,0} end; local u=tonumber(redis.call('HGET',KEYS[1],'uses') or '0'); if u>=tonumber(ARGV[3]) then return {-3,u} end; u=redis.call('HINCRBY',KEYS[1],'uses',1); return {1,u}`,
        { keys: [`read-token:${payload.jti}`], arguments: [visitorId, origin, String(READ_TOKEN_MAX_USES)] });
      if (Number(result?.[0]) === -2) { BotRiskClient.enqueue(visitorId, 'token_replay', { reason: 'redis_binding_mismatch' }); return sendReadAccessDenied(res, '读取凭证与当前访客不匹配'); }
      if (Number(result?.[0]) === -3) { BotRiskClient.enqueue(visitorId, 'token_replay', { reason: 'use_limit', uses: Number(result?.[1]) }); return sendReadAccessRequired(res, '读取凭证使用次数已达上限'); }
      if (Number(result?.[0]) === 1) record = { visitorId, origin, uses: Number(result?.[1]) - 1, expiresAt: Number(payload.exp) * 1000, redisCounted: true };
    }
    if (!record || record.expiresAt <= Date.now()) return sendReadAccessRequired(res);
    if (record.visitorId !== visitorId || record.origin !== origin) {
      return sendReadAccessDenied(res, '读取凭证与当前访客不匹配');
    }
    if (record.uses >= READ_TOKEN_MAX_USES) {
      BotRiskClient.enqueue(visitorId, 'token_replay', { jti: payload.jti.slice(0, 12), uses: record.uses });
      return sendReadAccessRequired(res, '读取凭证使用次数已达上限');
    }

    if (requiredScope === 'links:detail') {
      VisitorRiskService.recordDetailRead(visitorId, Number(req.params.id));
      const detailRestriction = VisitorRiskService.getReadRestriction(visitorId);
      if (detailRestriction) {
        BotRiskClient.enqueue(visitorId, 'sequential_detail_scan', {
          detailId: Number(req.params.id) || 0
        });
        res.set('Retry-After', String(detailRestriction.retryAfter));
        return res.status(429).json({
          code: 429,
          msg: IS_PRODUCTION ? '请求无法处理' : '当前读取会话请求异常，请稍后重试',
          data: null
        });
      }
    }

    record.uses += 1;
    if (!record.validReported) {
      record.validReported = true;
      BotRiskClient.enqueue(visitorId, 'valid_read_token', { scope: requiredScope });
    }
    issuedReadTokens.set(payload.jti, record, {
      ttl: Math.max(1, record.expiresAt - Date.now())
    });
    req.readAccess = { visitorId, jti: payload.jti, scopes };
    return next();
  };
}

module.exports = {
  READ_TOKEN_TTL_SECONDS,
  READ_TOKEN_MAX_USES,
  READ_ACCESS_SCOPES,
  issueReadAccessToken,
  requireReadAccess
};
