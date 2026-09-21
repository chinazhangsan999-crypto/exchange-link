'use strict';

const { authenticate } = require('../security/hmac');
const StorageService = require('../services/StorageService');

async function requireClient(req, res, next) {
  const clientId = String(req.get('X-Risk-Client') || '');
  const siteKey = String(req.get('X-Risk-Site') || clientId).slice(0, 64);
  const access = await StorageService.resolveClientAccess(clientId, siteKey);
  if (!access.ok) {
    return res.status(access.reason === 'unknown_client' ? 401 : 403)
      .json({ code: access.reason === 'unknown_client' ? 401 : 403, message: 'Risk integration disabled' });
  }
  const result = authenticate({
    clientId,
    secret: access.secret,
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
  if (!await StorageService.claimNonce(clientId, String(req.get('X-Risk-Nonce') || ''))) {
    return res.status(401).json({ code: 401, message: 'Unauthorized' });
  }
  if (access.legacy) {
    const provisioned = await StorageService.authorizeClient(clientId, siteKey, access.secret);
    if (!provisioned.ok) return res.status(403).json({ code: 403, message: 'Risk integration disabled' });
  }
  await StorageService.markClientUsed(clientId);
  req.riskClient = { clientId, siteKey, ...access };
  return next();
}

module.exports = { requireClient };
