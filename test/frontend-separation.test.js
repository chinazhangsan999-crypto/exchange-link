'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

test('分离模式仅接受可信边缘请求并保留入站 Claim 到 3 秒心跳闭环', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-frontend-separation-'));
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.NODE_ENV = 'test';
  process.env.PUBLIC_FRONTEND_MODE = 'separated';
  process.env.ADMIN_FRONTEND_ORIGIN = 'http://127.0.0.1:8787';
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';
  process.env.FRONTEND_PROXY_API_HOSTS = 'api-link.example.test';
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';
  process.env.INITIAL_ADMIN_PASSWORD = 'LocalTestPassword123';

  const database = require('../src/config/database');
  const SystemModel = require('../src/models/SystemModel');
  const FrontendOriginModel = require('../src/models/FrontendOriginModel');
  const MirrorModel = require('../src/models/MirrorModel');
  const FrontendProxyService = require('../src/services/FrontendProxyService');
  const app = require('../src/app');

  await SystemModel.initializeDatabase();
  await FrontendOriginModel.initializeFrontendOriginTable();
  await MirrorModel.initializeMirrorsTable();
  await FrontendOriginModel.replaceOrigins([{ origin: 'http://127.0.0.1:8787', enabled: true }]);
  FrontendProxyService.clearAllowedOriginCache();
  const partner = await database.run(`INSERT INTO partners(
    name, domain, url, category, is_approved, backlink_status, ping_status
  ) VALUES (?, ?, ?, ?, 1, 'valid', 'ok')`, [
    '测试来源站', 'partner.test', 'https://partner.test', '测试分类'
  ]);

  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const frontendOrigin = 'http://127.0.0.1:8787';
  const clientIp = '203.0.113.42';
  const userAgent = 'Mozilla/5.0 Chrome/122.0 Safari/537.36';

  function proxyHeaders(method, requestPath, rawBody = '') {
    const timestamp = Date.now();
    const nonce = `test_nonce_${Date.now()}_${Math.random().toString(36).slice(2)}`;
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
      }),
      'User-Agent': userAgent
    };
  }

  function requestStatusWithHost(requestPath, host) {
    return new Promise((resolve, reject) => {
      const request = http.request({
        hostname: '127.0.0.1',
        port: server.address().port,
        path: requestPath,
        headers: { Host: host }
      }, response => {
        response.resume();
        response.once('end', () => resolve(response.statusCode));
      });
      request.once('error', reject);
      request.end();
    });
  }

  try {
    const directRead = await fetch(`${baseUrl}/api/read/bootstrap`);
    assert.equal(directRead.status, 404);
    assert.equal((await fetch(`${baseUrl}/r/untrusted-sid`, { redirect: 'manual' })).status, 404);
    assert.equal((await fetch(`${baseUrl}/api/mirrors`)).status, 200);
    assert.equal(await requestStatusWithHost('/api/mirrors', 'api-link.example.test'), 404);
    assert.equal(await requestStatusWithHost('/api/health', 'api-link.example.test'), 200);

    const directAdminLogin = await fetch(`${baseUrl}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'LocalTestPassword123' })
    });
    assert.equal(directAdminLogin.status, 404);
    assert.equal((await fetch(`${baseUrl}/admin`, { redirect: 'manual' })).status, 404);

    const loginBody = JSON.stringify({ username: 'admin', password: 'LocalTestPassword123' });
    const login = await fetch(`${baseUrl}/api/admin/login`, {
      method: 'POST',
      headers: { ...proxyHeaders('POST', '/api/admin/login', loginBody), 'Content-Type': 'application/json' },
      body: loginBody
    });
    assert.equal(login.status, 200);
    assert.equal((await login.json()).data.token, undefined);
    const setCookies = typeof login.headers.getSetCookie === 'function'
      ? login.headers.getSetCookie() : [login.headers.get('set-cookie')];
    const adminCookieHeader = setCookies.filter(Boolean).map(value => value.split(';')[0]).join('; ');
    const csrf = /webring_admin_csrf=([^;]+)/.exec(adminCookieHeader)?.[1] || '';
    assert.ok(adminCookieHeader.includes('webring_admin='));
    assert.ok(csrf);
    const rejectedWithoutCsrf = await fetch(`${baseUrl}/api/admin/frontend-origins`, {
      method: 'PUT',
      headers: {
        ...proxyHeaders('PUT', '/api/admin/frontend-origins', JSON.stringify({ origins: [] })),
        'Content-Type': 'application/json', Cookie: adminCookieHeader
      },
      body: JSON.stringify({ origins: [] })
    });
    assert.equal(rejectedWithoutCsrf.status, 403);
    const savedOriginsBody = JSON.stringify({
      origins: [
        { origin: frontendOrigin, enabled: '1' },
        { origin: 'http://localhost:8788', enabled: '0' }
      ]
    });
    const savedOrigins = await fetch(`${baseUrl}/api/admin/frontend-origins`, {
      method: 'PUT',
      headers: {
        ...proxyHeaders('PUT', '/api/admin/frontend-origins', savedOriginsBody),
        'Content-Type': 'application/json',
        Cookie: adminCookieHeader,
        'X-CSRF-Token': csrf
      },
      body: savedOriginsBody
    });
    assert.equal(savedOrigins.status, 200);
    const originConfig = await (await fetch(`${baseUrl}/api/admin/frontend-origins`, {
      headers: { ...proxyHeaders('GET', '/api/admin/frontend-origins'), Cookie: adminCookieHeader }
    })).json();
    assert.equal(originConfig.data.frontendProxyConfigured, true);
    assert.equal(originConfig.data.publicFrontendMode, 'separated');
    assert.equal(originConfig.data.origins.length, 2);
    assert.equal(originConfig.data.origins.find(item => item.origin === 'http://localhost:8788').enabled, false);

    const oneTimeHeaders = proxyHeaders('GET', '/api/health');
    assert.equal((await fetch(`${baseUrl}/api/health`, { headers: oneTimeHeaders })).status, 200);
    assert.equal((await fetch(`${baseUrl}/api/health`, { headers: oneTimeHeaders })).status, 401);

    const landingBody = JSON.stringify({
      requestPath: '/',
      referer: 'https://news.partner.test/article',
      userAgent
    });
    const landing = await fetch(`${baseUrl}/internal/frontend/landing`, {
      method: 'POST',
      headers: {
        ...proxyHeaders('POST', '/internal/frontend/landing', landingBody),
        'Content-Type': 'application/json'
      },
      body: landingBody
    });
    assert.equal(landing.status, 200);
    const landingJson = await landing.json();
    assert.equal(landingJson.data.status, 'claim_issued');
    assert.equal(landingJson.data.claimIssued, true);

    const cookies = landing.headers.getSetCookie().map(value => value.split(';', 1)[0]);
    const cookieHeader = cookies.join('; ');
    assert.match(cookieHeader, /guest_visitor_id=/);
    assert.match(cookieHeader, /track_session=/);

    await database.run('UPDATE inflow_claim_tokens SET started_at_ms = ? WHERE partner_id = ?', [
      Date.now() - 4000,
      partner.id
    ]);

    const pingBody = JSON.stringify({
      fingerprint: {
        resolution: '1920x1080',
        language: 'zh-CN',
        platform: 'Win32',
        webdriver: false
      }
    });
    const ping = await fetch(`${baseUrl}/api/track/ping`, {
      method: 'POST',
      headers: {
        ...proxyHeaders('POST', '/api/track/ping', pingBody),
        'Content-Type': 'application/json',
        Cookie: cookieHeader
      },
      body: pingBody
    });
    assert.equal(ping.status, 200);
    const pingJson = await ping.json();
    assert.equal(pingJson.data.newlyCounted, true);

    const inbound = await database.get('SELECT * FROM inbound_logs WHERE link_id = ?', [partner.id]);
    assert.equal(inbound.client_ip, clientIp);
    assert.equal(inbound.observed_domain, 'partner.test');
    assert.equal(inbound.attribution_method, 'domain_only');
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
