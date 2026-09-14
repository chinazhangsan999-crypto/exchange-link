'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

function solveProof(challenge) {
  for (let solution = 0; solution <= 1_000_000; solution += 1) {
    const digest = crypto.createHash('sha256')
      .update(`${challenge.challengeId}:${challenge.salt}:${solution}`)
      .digest();
    let leadingBits = 0;
    for (const byte of digest) {
      if (byte === 0) { leadingBits += 8; continue; }
      for (let mask = 0x80; mask > 0 && (byte & mask) === 0; mask >>= 1) leadingBits += 1;
      break;
    }
    if (leadingBits >= challenge.difficultyBits) return solution;
  }
  throw new Error('测试未找到计算校验解');
}

test('公开展示接口经可信边缘使用短效读取凭证且源站首页保持关闭', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-read-access-'));
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';
  process.env.INITIAL_ADMIN_PASSWORD = 'LocalTestPassword123';
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';

  const database = require('../src/config/database');
  const SystemModel = require('../src/models/SystemModel');
  const AdsModel = require('../src/models/AdsModel');
  const FrontendOriginModel = require('../src/models/FrontendOriginModel');
  const FrontendProxyService = require('../src/services/FrontendProxyService');
  const app = require('../src/app');

  await SystemModel.initializeDatabase();
  await AdsModel.initializeAdsTable();
  await FrontendOriginModel.initializeFrontendOriginTable();
  const frontendOrigin = 'http://127.0.0.1:8787';
  await FrontendOriginModel.replaceOrigins([{ origin: frontendOrigin, enabled: true }]);
  FrontendProxyService.clearAllowedOriginCache();
  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  function proxyHeaders(method, requestPath, rawBody = '') {
    const timestamp = Date.now();
    const nonce = `read_test_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const clientIp = '203.0.113.42';
    return {
      'X-Frontend-Origin': frontendOrigin,
      'X-Verified-Client-IP': clientIp,
      'X-Proxy-Timestamp': String(timestamp),
      'X-Proxy-Nonce': nonce,
      'X-Proxy-Signature': FrontendProxyService.signProxyRequest({
        timestamp,
        nonce,
        method,
        path: requestPath,
        origin: frontendOrigin,
        clientIp,
        rawBody: Buffer.from(rawBody)
      })
    };
  }

  function edgeFetch(requestPath, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const rawBody = typeof options.body === 'string' ? options.body : '';
    return fetch(`${baseUrl}${requestPath}`, {
      ...options,
      headers: {
        ...proxyHeaders(method, requestPath, rawBody),
        ...(options.headers || {})
      }
    });
  }

  async function bootstrap(cookie = '') {
    const response = await edgeFetch('/api/read/bootstrap', {
      headers: cookie ? { Cookie: cookie } : {}
    });
    const body = await response.json();
    const visitorCookie = response.headers.getSetCookie()
      .find(value => value.startsWith('guest_visitor_id='))
      .split(';', 1)[0];
    return { response, body, visitorCookie };
  }

  try {
    const homepage = await fetch(`${baseUrl}/`);
    assert.equal(homepage.status, 404);

    const visitorA = await bootstrap();
    assert.equal(visitorA.response.status, 200);
    assert.equal(visitorA.response.headers.get('cache-control'), 'private, no-store');
    assert.equal(visitorA.body.code, 200);
    assert.equal(visitorA.body.data.expiresIn, 60);
    assert.ok(visitorA.body.data.token);

    const missingToken = await edgeFetch('/api/links', {
      headers: { Cookie: visitorA.visitorCookie }
    });
    assert.equal(missingToken.status, 428);

    const allowed = await edgeFetch('/api/links', {
      headers: {
        Cookie: visitorA.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.headers.get('cache-control'), 'private, no-store');
    assert.equal((await allowed.json()).code, 200);

    const visitorB = await bootstrap();
    const crossVisitor = await edgeFetch('/api/links', {
      headers: {
        Cookie: visitorB.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(crossVisitor.status, 403);

    const wrongScope = await edgeFetch('/api/showcase', {
      headers: {
        Cookie: visitorA.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(wrongScope.status, 200);

    const firstTrap = await edgeFetch('/api/sys-trap/trapdoor', {
      headers: { Cookie: visitorA.visitorCookie }
    });
    assert.equal(firstTrap.status, 204);
    assert.equal(firstTrap.headers.get('cache-control'), 'private, no-store');
    const afterFirstSignal = await edgeFetch('/api/links', {
      headers: {
        Cookie: visitorA.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(afterFirstSignal.status, 200);

    const secondTrap = await edgeFetch('/api/sys-trap/trapdoor', {
      headers: { Cookie: visitorA.visitorCookie }
    });
    assert.equal(secondTrap.status, 204);
    const restrictedVisitor = await edgeFetch('/api/links', {
      headers: {
        Cookie: visitorA.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(restrictedVisitor.status, 429);
    assert.equal(restrictedVisitor.headers.get('retry-after'), '30');

    const proofBootstrap = await edgeFetch('/api/read/bootstrap', {
      headers: { Cookie: visitorA.visitorCookie }
    });
    const proofBody = await proofBootstrap.json();
    assert.equal(proofBootstrap.status, 428);
    assert.equal(proofBody.data.proofRequired, true);
    const proofPayload = {
      challengeId: proofBody.data.challenge.challengeId,
      solution: solveProof(proofBody.data.challenge)
    };
    const proofRawBody = JSON.stringify(proofPayload);
    const proofResponse = await edgeFetch('/api/read/proof', {
      method: 'POST',
      headers: { Cookie: visitorA.visitorCookie, 'Content-Type': 'application/json' },
      body: proofRawBody
    });
    assert.equal(proofResponse.status, 200);
    const replayResponse = await edgeFetch('/api/read/proof', {
      method: 'POST',
      headers: { Cookie: visitorA.visitorCookie, 'Content-Type': 'application/json' },
      body: proofRawBody
    });
    assert.equal(replayResponse.status, 400);
    const recoveredBootstrap = await edgeFetch('/api/read/bootstrap', {
      headers: { Cookie: visitorA.visitorCookie }
    });
    assert.equal(recoveredBootstrap.status, 200);

    // 两个访客来自同一个测试 IP；A 的风险状态不得连坐 B。
    const sameNatOtherVisitor = await edgeFetch('/api/links', {
      headers: {
        Cookie: visitorB.visitorCookie,
        'X-Read-Token': visitorB.body.data.token
      }
    });
    assert.equal(sameNatOtherVisitor.status, 200);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
