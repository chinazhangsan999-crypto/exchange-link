'use strict';

const crypto = require('crypto');
const DecisionService = require('../services/DecisionService');
const StorageService = require('../services/StorageService');

function siteKey(req) {
  return String(req.riskClient?.siteKey || req.riskClient?.clientId || '').slice(0, 64);
}

async function events(req, res) {
  const inputs = Array.isArray(req.body?.events) ? req.body.events : [];
  if (!inputs.length || inputs.length > 500) {
    return res.status(400).json({ code: 400, message: 'events must contain 1-500 items' });
  }
  const result = DecisionService.applyEvents(siteKey(req), inputs);
  result.decisions = await StorageService.applyManualControls(siteKey(req), result.acceptedEvents, result.decisions);
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

async function policy(req, res) {
  const control = await StorageService.getSiteControl(siteKey(req));
  return res.json({
    code: 200,
    data: {
      version: DecisionService.DEFAULT_POLICY_VERSION,
      thresholds: { observe: 25, silentChallenge: 50, strongChallenge: 75, deny: 90 },
      enforcement: control,
      hash: crypto.createHash('sha256').update(DecisionService.DEFAULT_POLICY_VERSION).digest('hex')
    }
  });
}

module.exports = { events, decisions, evaluate, policy };
