'use strict';

const crypto = require('crypto');
const DecisionService = require('../services/DecisionService');
const StorageService = require('../services/StorageService');

function siteKey(req) {
  return String(req.get('X-Risk-Site') || req.riskClient?.clientId || '').slice(0, 64);
}

async function events(req, res) {
  const inputs = Array.isArray(req.body?.events) ? req.body.events : [];
  if (!inputs.length || inputs.length > 500) {
    return res.status(400).json({ code: 400, message: 'events must contain 1-500 items' });
  }
  const result = DecisionService.applyEvents(siteKey(req), inputs);
  await StorageService.persistBatch(result.acceptedEvents, result.decisions);
  return res.json({ code: 200, data: result });
}

async function decisions(req, res) {
  return res.json({
    code: 200,
    data: await StorageService.listDelta(siteKey(req), req.query.cursor, Math.min(1000, Number(req.query.limit) || 1000))
  });
}

async function evaluate(req, res) {
  const visitorHash = String(req.body?.visitorHash || '').toLowerCase();
  if (!/^[a-f0-9]{32,128}$/.test(visitorHash)) {
    return res.status(400).json({ code: 400, message: 'invalid visitorHash' });
  }
  return res.json({ code: 200, data: await StorageService.evaluate(siteKey(req), visitorHash) });
}

function policy(req, res) {
  return res.json({
    code: 200,
    data: {
      version: DecisionService.DEFAULT_POLICY_VERSION,
      thresholds: { observe: 25, silentChallenge: 50, strongChallenge: 75, deny: 90 },
      hash: crypto.createHash('sha256').update(DecisionService.DEFAULT_POLICY_VERSION).digest('hex')
    }
  });
}

module.exports = { events, decisions, evaluate, policy };
