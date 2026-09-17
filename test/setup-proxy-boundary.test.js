'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('protected origin allows only health and one-time setup paths without proxy headers', async () => {
  process.env.NODE_ENV = 'test';
  process.env.FRONTEND_PROXY_API_HOSTS = 'origin.example.com';

  const { acceptTrustedFrontendProxy } = require('../src/middlewares/frontendProxy');

  async function invoke(path) {
    const result = { status: null, ended: false, next: false };
    const request = {
      path,
      headers: { host: 'origin.example.com' },
      get() { return undefined; }
    };
    const response = {
      status(value) { result.status = value; return this; },
      end() { result.ended = true; return this; }
    };
    await acceptTrustedFrontendProxy(request, response, () => { result.next = true; });
    return result;
  }

  for (const path of ['/api/health', '/setup', '/setup/client.js', '/api/setup/status', '/api/setup/deploy']) {
    assert.deepEqual(await invoke(path), { status: null, ended: false, next: true });
  }
  assert.deepEqual(await invoke('/api/links'), { status: 404, ended: true, next: false });
  assert.deepEqual(await invoke('/api/admin/login'), { status: 404, ended: true, next: false });
});
