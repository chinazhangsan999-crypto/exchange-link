'use strict';

const StorageService = require('../services/StorageService');

async function requireMaintenanceRead(req, res, next) {
  res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  const authorization = String(req.get('Authorization') || '');
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7).trim() : '';
  if (!await StorageService.consumeMaintenanceToken(token)) {
    return res.status(401).json({ code: 401, message: 'Unauthorized' });
  }
  return next();
}

module.exports = { requireMaintenanceRead };
