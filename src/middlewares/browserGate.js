'use strict';

const { IS_PRODUCTION } = require('../config/env');
const { ensureVisitorIdentity, getCookie } = require('./rateLimit');
const BrowserChallengeService = require('../services/BrowserChallengeService');
const BotRiskClient = require('../services/BotRiskClient');

function requireBrowserAccess(req, res, next) {
  const visitorId = ensureVisitorIdentity(req, res);
  const token = getCookie(req, BrowserChallengeService.COOKIE_NAME);
  const access = BrowserChallengeService.verifyAccessToken(token, visitorId, req.get('user-agent') || '');
  req.browserAccess = access;
  const decision = BotRiskClient.getDecision(visitorId);
  if (!BrowserChallengeService.isEnforced() || !decision?.enforce || access) return next();
  if (decision.decision === 'deny') {
    return res.status(403).json({ code: 403, msg: '请求无法处理', data: null });
  }
  if (!['silent_challenge', 'strong_challenge'].includes(decision.decision)) return next();
  res.set('Cache-Control', 'private, no-store');
  return res.status(428).json({
    code: 428,
    msg: IS_PRODUCTION ? '请求无法处理' : '需要浏览器静默验证',
    data: { browserVerificationRequired: true }
  });
}

module.exports = { requireBrowserAccess };
