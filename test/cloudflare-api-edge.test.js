'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

test('API Edge 白名单使用 multipart/form-data 更新 Worker Settings', async () => {
  const CredentialStore = require('../src/services/IntegrationCredentialStore');
  const originalConfig = CredentialStore.cloudflareApiEdgeConfig;
  const originalFetch = global.fetch;
  const calls = [];

  CredentialStore.cloudflareApiEdgeConfig = () => ({
    accountId: 'a'.repeat(32),
    workerName: 'api-worker',
    apiToken: 'test-token-012345678901234567890'
  });
  global.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if ((options.method || 'GET') === 'GET') {
      return new Response(JSON.stringify({
        success: true,
        result: { bindings: [{ name: 'API_ORIGIN', type: 'plain_text', text: 'https://origin.example.com' }] }
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify({ success: true, result: {} }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  };

  try {
    delete require.cache[require.resolve('../src/services/CloudflareApiEdgeService')];
    const service = require('../src/services/CloudflareApiEdgeService');
    const result = await service.syncAllowedOrigins([{ origin: 'https://front.example.com', enabled: true }]);
    assert.equal(result.synchronized, true);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].options.method, 'PATCH');
    assert.ok(calls[1].options.body instanceof FormData);
    assert.equal(calls[1].options.headers['Content-Type'], undefined);
    const settings = JSON.parse(await calls[1].options.body.get('settings').text());
    assert.deepEqual(settings.bindings, [
      { name: 'API_ORIGIN', type: 'plain_text', text: 'https://origin.example.com' },
      { name: 'ALLOWED_FRONTEND_ORIGINS', type: 'plain_text', text: 'https://front.example.com' }
    ]);
  } finally {
    CredentialStore.cloudflareApiEdgeConfig = originalConfig;
    global.fetch = originalFetch;
  }
});
