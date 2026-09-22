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

function cleanString(value, max = 160) { return String(value || '').trim().slice(0, max); }

async function inventory(req, res) {
  const input = req.body || {};
  if (input.schemaVersion !== 'inventory-v1' || !Array.isArray(input.components)
    || !Array.isArray(input.capabilities) || input.components.length > 100 || input.capabilities.length > 100) {
    return res.status(400).json({ code: 400, message: 'invalid inventory' });
  }
  const data = await StorageService.saveRuntimeInventory({
    siteKey: siteKey(req), clientId: req.riskClient.clientId,
    schemaVersion: input.schemaVersion,
    appVersion: cleanString(input.appVersion, 80), gitCommit: cleanString(input.gitCommit, 80),
    nodeVersion: cleanString(input.nodeVersion, 80), protocolVersion: cleanString(input.riskProtocolVersion, 80),
    components: input.components, capabilities: input.capabilities,
    deployedAt: input.deployedAt || null
  });
  return res.json({ code: 200, data });
}

async function advisories(req, res) {
  return res.json({ code: 200, data: await StorageService.listAgentAdvisories(siteKey(req)) });
}

async function testResults(req, res) {
  const input = req.body || {};
  if (!/^[a-z0-9_-]{2,64}$/i.test(String(input.projectKey || ''))
    || !cleanString(input.targetVersion, 120) || typeof input.passed !== 'boolean') {
    return res.status(400).json({ code: 400, message: 'invalid test result' });
  }
  const data = await StorageService.saveMaintenanceTestResult({
    siteKey: siteKey(req), clientId: req.riskClient.clientId,
    projectKey: cleanString(input.projectKey, 64), targetVersion: cleanString(input.targetVersion, 120),
    testCommit: cleanString(input.testCommit, 80), automated: input.automated,
    browsers: input.browsers, falsePositiveDelta: input.falsePositiveDelta,
    recommendation: cleanString(input.recommendation, 500), passed: input.passed,
    testedAt: input.testedAt || new Date().toISOString()
  });
  return res.json({ code: 200, data });
}

module.exports = { events, decisions, evaluate, policy, inventory, advisories, testResults };
