'use strict';

const { CLIENTS } = require('../config/env');
const { authenticate } = require('../security/hmac');
const StorageService = require('../services/StorageService');

async function requireClient(req, res, next) {
  const clientId = String(req.get('X-Risk-Client') || '');
  const secret = CLIENTS[clientId];
  const result = authenticate({
    clientId,
    secret,
    method: req.method,
    pathAndQuery: req.originalUrl,
    timestamp: req.get('X-Risk-Timestamp'),
    nonce: String(req.get('X-Risk-Nonce') || ''),
    signature: String(req.get('X-Risk-Signature') || ''),
    body: req.rawBody || Buffer.alloc(0)
  });
  if (!result.ok) {
    return res.status(401).json({ code: 401, message: 'Unauthorized' });
  }
  const siteKey = String(req.get('X-Risk-Site') || clientId).slice(0, 64);
  const access = await StorageService.authorizeClient(clientId, siteKey, secret);
  if (!access.ok) {
    return res.status(403).json({ code: 403, message: 'Risk integration disabled' });
  }
  req.riskClient = { clientId, siteKey };
  return next();
}

module.exports = { requireClient };
