'use strict';

const crypto = require('crypto');

const baseUrl = String(process.env.BOT_RISK_BASE_URL || 'http://127.0.0.1:4100').replace(/\/$/, '');
const clientId = String(process.env.BOT_RISK_CLIENT_ID || 'nav-main');
const siteKey = String(process.env.BOT_RISK_SITE_KEY || 'local-test');
const secret = String(process.env.BOT_RISK_CLIENT_SECRET || '');

if (secret.length < 32) throw new Error('BOT_RISK_CLIENT_SECRET must contain at least 32 characters');

function signature(method, pathAndQuery, body, timestamp, nonce) {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const canonical = [method, pathAndQuery, timestamp, nonce, bodyHash].join('\n');
  return crypto.createHmac('sha256', secret).update(canonical).digest('hex');
}

async function signedRequest(method, pathAndQuery, payload) {
  const body = payload === undefined ? '' : JSON.stringify(payload);
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(16).toString('hex');
  const response = await fetch(`${baseUrl}${pathAndQuery}`, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      'x-risk-client': clientId,
      'x-risk-site': siteKey,
      'x-risk-timestamp': timestamp,
      'x-risk-nonce': nonce,
      'x-risk-signature': signature(method, pathAndQuery, body, timestamp, nonce)
    },
    ...(body ? { body } : {})
  });
  const data = await response.json();
  if (!response.ok) throw new Error(`${method} ${pathAndQuery} returned ${response.status}: ${JSON.stringify(data)}`);
  return data;
}

async function main() {
  const health = await fetch(`${baseUrl}/health`).then(response => response.json());
  const ready = await fetch(`${baseUrl}/ready`).then(response => response.json());
  if (!health.ok || !ready.ready) throw new Error('risk center is not ready');

  const verifyVisitorHash = String(process.env.BOT_RISK_VERIFY_HASH || '').toLowerCase();
  if (verifyVisitorHash) {
    const evaluated = await signedRequest('POST', '/v1/evaluate', { visitorHash: verifyVisitorHash });
    if (evaluated.data?.decision !== 'deny') throw new Error('persisted decision was not restored after restart');
    process.stdout.write(JSON.stringify({
      ok: true,
      persistenceVerified: true,
      decision: evaluated.data.decision,
      score: evaluated.data.score,
      visitorHash: verifyVisitorHash
    }));
    return;
  }

  const visitorHash = crypto.randomBytes(32).toString('hex');
  const eventId = crypto.randomUUID();
  const eventResult = await signedRequest('POST', '/v1/events/batch', {
    events: [{
      eventId,
      visitorHash,
      eventType: 'known_ai_crawler',
      occurredAt: Date.now(),
      evidence: { test: 'docker-integration-smoke' }
    }]
  });
  if (eventResult.data?.accepted !== 1 || eventResult.data?.decisions?.[0]?.decision !== 'deny') {
    throw new Error(`unexpected decision: ${JSON.stringify(eventResult)}`);
  }

  const delta = await signedRequest('GET', '/v1/decisions/delta?cursor=0&limit=10');
  const persisted = delta.data?.items?.find(item => item.subjectHash === visitorHash);
  if (!persisted || persisted.score !== 100 || !['observe', 'deny'].includes(persisted.decision)) {
    throw new Error(`persisted decision not found: ${JSON.stringify(delta)}`);
  }

  const evaluated = await signedRequest('POST', '/v1/evaluate', { visitorHash });
  if (evaluated.data?.score !== 100 || !['observe', 'deny'].includes(evaluated.data?.decision)) {
    throw new Error('Redis/PostgreSQL evaluation did not return the persisted score');
  }

  const inventory = await signedRequest('POST', '/v1/agent/inventory', {
    schemaVersion: 'inventory-v1', appVersion: 'smoke-test', gitCommit: 'smoke-test',
    nodeVersion: process.version, riskProtocolVersion: 'risk-agent-v1',
    deployedAt: new Date().toISOString(),
    components: [{ key: 'botd', packageVersion: '2.0.0', assetVersion: '2.0.0', assetSha256: 'a'.repeat(64) }],
    capabilities: ['botd', 'browser_pow', 'read_token', 'risk_decision_sync']
  });
  if (inventory.data?.siteKey !== siteKey) throw new Error('runtime inventory was not accepted');

  const advisories = await signedRequest('GET', '/v1/agent/advisories');
  if (!Array.isArray(advisories.data)) throw new Error('advisories response is invalid');

  const testResult = await signedRequest('POST', '/v1/agent/test-results', {
    projectKey: 'botd', targetVersion: 'smoke-test', testCommit: 'smoke-test',
    automated: { node: 'passed' }, browsers: { chromium: 'passed' },
    falsePositiveDelta: 0, recommendation: 'smoke test only', passed: true,
    testedAt: new Date().toISOString()
  });
  if (testResult.data?.projectKey !== 'botd') throw new Error('test result was not accepted');

  process.stdout.write(JSON.stringify({
    ok: true,
    health,
    ready,
    accepted: eventResult.data.accepted,
    decision: evaluated.data.decision,
    score: evaluated.data.score,
    inventoryReported: true,
    advisoryCount: advisories.data.length,
    testResultReported: true,
    persistedSequence: persisted.sequence,
    visitorHash
  }));
}

main().catch(error => {
  console.error(error?.stack || error);
  process.exitCode = 1;
});
