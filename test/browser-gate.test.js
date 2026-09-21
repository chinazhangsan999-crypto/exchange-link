'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

function solveProof(challenge) {
  for (let solution = 0; solution < 2_000_000; solution += 1) {
    const digest = crypto.createHash('sha256')
      .update(`${challenge.challengeId}:${challenge.salt}:${solution}`)
      .digest();
    let bits = 0;
    for (const byte of digest) {
      if (byte === 0) { bits += 8; continue; }
      for (let mask = 0x80; mask > 0 && (byte & mask) === 0; mask >>= 1) bits += 1;
      break;
    }
    if (bits >= challenge.difficultyBits) return solution;
  }
  throw new Error('未找到测试解');
}

test('强制模式下浏览器静默校验签发受访客与 UA 绑定的通行证', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-browser-gate-'));
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';
  process.env.EDGE_ACCESS_SECRET = 'test-edge-access-secret-012345678901';
  process.env.BOT_GATE_MODE = 'enforce';
  process.env.BOT_RISK_CENTER_ENABLED = '1';
  process.env.BOT_RISK_CENTER_URL = 'http://127.0.0.1:9';
  process.env.BOT_RISK_CLIENT_ID = 'nav-test';
  process.env.BOT_RISK_CLIENT_SECRET = 'test-risk-client-secret-012345678901';
  process.env.BOT_RISK_SITE_KEY = 'webring-test';
  process.env.INITIAL_ADMIN_PASSWORD = 'LocalTestPassword123';

  const database = require('../src/config/database');
  const SystemModel = require('../src/models/SystemModel');
  const FrontendOriginModel = require('../src/models/FrontendOriginModel');
  const FrontendProxyService = require('../src/services/FrontendProxyService');
  const BotRiskClient = require('../src/services/BotRiskClient');
  const LocalRiskDecisionCache = require('../src/services/LocalRiskDecisionCache');
  const app = require('../src/app');
  await SystemModel.initializeDatabase();
  await FrontendOriginModel.initializeFrontendOriginTable();
  const origin = 'http://127.0.0.1:8787';
  await FrontendOriginModel.replaceOrigins([{ origin, enabled: true }]);
  FrontendProxyService.clearAllowedOriginCache();
  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const userAgent = 'Mozilla/5.0 TestBrowser/1.0';

  function proxyHeaders(method, requestPath, rawBody = '') {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(12).toString('hex');
    const clientIp = '203.0.113.88';
    return {
      'User-Agent': userAgent,
      'X-Frontend-Origin': origin,
      'X-Verified-Client-IP': clientIp,
      'X-Proxy-Timestamp': String(timestamp),
      'X-Proxy-Nonce': nonce,
      'X-Proxy-Signature': FrontendProxyService.signProxyRequest({
        timestamp, nonce, method, path: requestPath, origin, clientIp, rawBody: Buffer.from(rawBody)
      })
    };
  }

  async function edgeFetch(requestPath, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const rawBody = typeof options.body === 'string' ? options.body : '';
    return fetch(`${base}${requestPath}`, {
      ...options,
      headers: { ...proxyHeaders(method, requestPath, rawBody), ...(options.headers || {}) }
    });
  }

  try {
    const normal = await edgeFetch('/api/read/bootstrap');
    assert.equal(normal.status, 200);
    const visitorCookie = normal.headers.getSetCookie()
      .find(value => value.startsWith('guest_visitor_id='))
      .split(';', 1)[0];
    const visitorToken = decodeURIComponent(visitorCookie.slice(visitorCookie.indexOf('=') + 1));
    const visitorId = jwt.verify(visitorToken, process.env.GUEST_JWT_SECRET).visitorId;
    LocalRiskDecisionCache.setMany([{
      sequence: 1,
      subjectHash: BotRiskClient.subjectHash(visitorId),
      score: 65,
      decision: 'silent_challenge',
      reasons: ['test'],
      policyVersion: 'test-1',
      expiresAt: Date.now() + 60_000
    }]);
    const blocked = await edgeFetch('/api/read/bootstrap', { headers: { Cookie: visitorCookie } });
    assert.equal(blocked.status, 428);

    const challengeResponse = await edgeFetch('/api/browser/challenge', {
      headers: { Cookie: visitorCookie }
    });
    assert.equal(challengeResponse.status, 200);
    const challenge = (await challengeResponse.json()).data.challenge;
    const solution = solveProof(challenge);
    const payload = JSON.stringify({ challengeId: challenge.challengeId, solution, webdriver: false, botD: { bot: false } });
    const verified = await edgeFetch('/api/browser/verify', {
      method: 'POST',
      headers: { Cookie: visitorCookie, 'Content-Type': 'application/json' },
      body: payload
    });
    assert.equal(verified.status, 200);
    const accessCookie = verified.headers.getSetCookie()
      .find(value => value.startsWith('browser_access_token='))
      .split(';', 1)[0];

    const allowed = await edgeFetch('/api/read/bootstrap', {
      headers: { Cookie: `${visitorCookie}; ${accessCookie}` }
    });
    assert.equal(allowed.status, 200);

    const wrongUa = await fetch(`${base}/api/read/bootstrap`, {
      headers: {
        ...proxyHeaders('GET', '/api/read/bootstrap'),
        'User-Agent': 'Mozilla/5.0 DifferentBrowser/1.0',
        Cookie: `${visitorCookie}; ${accessCookie}`
      }
    });
    assert.equal(wrongUa.status, 428);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
