'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

test('生成独立前台时可幂等应用 Zone 安全基线，免费版受限项不会中断流程', async () => {
  const databasePath = path.join(os.tmpdir(), `webring-cloudflare-security-${process.pid}-${Date.now()}.db`);
  process.env.DB_PATH = databasePath;
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';

  const CredentialStore = require('../src/services/IntegrationCredentialStore');
  const database = require('../src/config/database');
  const originalBootstrap = CredentialStore.cloudflareBootstrapConfig;
  const originalFetch = global.fetch;
  const calls = [];
  let rulesetExists = false;

  CredentialStore.cloudflareBootstrapConfig = () => ({ adminDomain: 'admin.example.com' });
  global.fetch = async (url, options = {}) => {
    const target = String(url);
    const method = options.method || 'GET';
    calls.push({ target, method, body: options.body ? JSON.parse(options.body) : null });
    const response = (status, result, errors = []) => new Response(JSON.stringify({
      success: status >= 200 && status < 300,
      result,
      errors
    }), { status, headers: { 'Content-Type': 'application/json' } });

    if (method === 'GET' && target.includes('/zones?')) {
      return response(200, [{ id: 'zone-123', name: 'example.com' }]);
    }
    if (method === 'PATCH' && target.includes('/settings/')) {
      return response(200, { value: JSON.parse(options.body).value });
    }
    if (method === 'PUT' && target.endsWith('/bot_management')) {
      return response(403, null, [{ code: 10000, message: 'Authentication error' }]);
    }
    if (method === 'GET' && target.endsWith('/rulesets/phases/http_request_firewall_custom/entrypoint')) {
      return rulesetExists
        ? response(200, { id: 'ruleset-1', rules: [
          { id: 'rule-1', description: 'Block scripted readers on read APIs' },
          { id: 'rule-2', description: 'Challenge empty UA on read APIs' },
          { id: 'rule-3', description: 'webring-admin-entry-managed-challenge' }
        ] })
        : response(404, null, [{ code: 10000, message: 'not found' }]);
    }
    if (method === 'POST' && target.endsWith('/rulesets')) {
      rulesetExists = true;
      return response(200, { id: 'ruleset-1' });
    }
    if (method === 'PATCH' && /\/rulesets\/ruleset-1\/rules\/rule-[123]$/.test(target)) {
      return response(200, { id: target.slice(-6) });
    }
    throw new Error(`未预期的 Cloudflare 请求：${method} ${target}`);
  };

  try {
    delete require.cache[require.resolve('../src/services/CloudflarePublicFrontendService')];
    const service = require('../src/services/CloudflarePublicFrontendService');
    const profile = { accountId: 'a'.repeat(32), apiToken: 'test-token-012345678901234567890' };

    const first = await service.ensureZoneSecurityBaseline(profile, 'example.com');
    const second = await service.ensureZoneSecurityBaseline(profile, 'example.com');

    assert.deepEqual(Object.keys(first.settings), ['tls_1_3', 'min_tls_version', 'http3', 'challenge_ttl']);
    assert.ok(Object.values(first.settings).every(item => item.applied === true));
    assert.equal(first.botProtection.applied, false);
    assert.equal(first.botProtection.managedByDashboard, true);
    assert.equal(first.securityRules.created, true);
    assert.deepEqual(first.securityRules.rules, [
      'Block scripted readers on read APIs',
      'Challenge empty UA on read APIs',
      'webring-admin-entry-managed-challenge'
    ]);
    assert.equal(second.securityRules.created, false);
    assert.equal(second.securityRules.updatedCount, 3);
    assert.equal(calls.filter(call => call.method === 'POST' && call.target.endsWith('/rulesets')).length, 1);
    assert.equal(calls.filter(call => call.method === 'PATCH' && /\/rulesets\/ruleset-1\/rules\/rule-[123]$/.test(call.target)).length, 3);
    assert.equal(calls.filter(call => call.method === 'PATCH' && call.target.includes('/settings/')).length, 8);
  } finally {
    CredentialStore.cloudflareBootstrapConfig = originalBootstrap;
    global.fetch = originalFetch;
    await database.closeDatabase();
    for (const suffix of ['', '-wal', '-shm']) fs.rmSync(`${databasePath}${suffix}`, { force: true });
  }
});

test('独立前台生成界面在提交前后都提醒免费版手动开启 Bot Fight 模式', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'admin', 'review.js'), 'utf8');
  assert.match(source, /免费版提醒：.*手动开启 Bot Fight 模式/);
  assert.match(source, /独立前台生成流程已完成/);
  assert.match(source, /同一根域只需开启一次/);
});
