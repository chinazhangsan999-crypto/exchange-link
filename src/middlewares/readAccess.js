'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { LRUCache } = require('lru-cache');
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

function issueReadAccessToken(req, res) {
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
  res.set('Cache-Control', 'private, no-store');
  return { token, expiresIn: READ_TOKEN_TTL_SECONDS, expiresAt };
}

function requireReadAccess(requiredScope) {
  if (!READ_ACCESS_SCOPES.includes(requiredScope)) {
    throw new Error(`未知的读取凭证 scope: ${requiredScope}`);
  }

  return (req, res, next) => {
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
      || typeof payload?.jti !== 'string'
      || !scopes.includes(requiredScope)) {
      return sendReadAccessDenied(res, '读取凭证与当前访客或接口不匹配');
    }

    const record = issuedReadTokens.get(payload.jti);
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
