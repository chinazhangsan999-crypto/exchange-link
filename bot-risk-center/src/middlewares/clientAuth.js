'use strict';

const { CLIENTS } = require('../config/env');
const { authenticate } = require('../security/hmac');

function requireClient(req, res, next) {
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
  req.riskClient = { clientId };
  return next();
}

module.exports = { requireClient };
