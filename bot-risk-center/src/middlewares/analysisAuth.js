'use strict';

const StorageService = require('../services/StorageService');

function requireAnalysisScope(scope) {
  return async function analysisAuthorization(req, res, next) {
    res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    const authorization = String(req.get('Authorization') || '');
    const token = authorization.startsWith('Bearer ') ? authorization.slice(7).trim() : '';
    const access = await StorageService.consumeAnalysisToken(token, scope);
    if (!access) return res.status(401).json({ code: 401, message: 'Unauthorized' });
    req.analysisAccess = access;
    return next();
  };
}

module.exports = { requireAnalysisScope };
