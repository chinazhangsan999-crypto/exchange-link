'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const databasePath = path.join(os.tmpdir(), `webring-cloudflare-bootstrap-${process.pid}-${Date.now()}.db`);
process.env.DB_PATH = databasePath;
test.after(async () => {
  const database = require('../src/config/database');
  await database.closeDatabase();
  for (const suffix of ['', '-wal', '-shm']) fs.rmSync(`${databasePath}${suffix}`, { force: true });
});

test('网页向导在服务端部署 API 与后台 Worker，且不回传 Cloudflare Token', async () => {
  process.env.NODE_ENV = 'test';
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';

  const CredentialStore = require('../src/services/IntegrationCredentialStore');
  const FrontendOriginModel = require('../src/models/FrontendOriginModel');
  let edge = { accountId: '', workerName: '', apiToken: '' };
  let bootstrap = { originUrl: '', apiDomain: '', apiWorkerName: '', adminDomain: '', adminWorkerName: '' };
  CredentialStore.cloudflareApiEdgeConfig = () => edge;
  CredentialStore.cloudflareBootstrapConfig = () => bootstrap;
  CredentialStore.saveCloudflareApiEdge = async value => { edge = { ...value }; };
  CredentialStore.saveCloudflareBootstrap = async value => { bootstrap = { ...value }; };
  FrontendOriginModel.listAllOrigins = async () => [
    { origin: 'https://front-a.example.com', enabled: 1 },
    { origin: 'https://disabled.example.com', enabled: 0 }
  ];

  const calls = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), method: options.method || 'GET', body: options.body });
    if (!String(url).startsWith('https://api.cloudflare.com/')) return new Response('', { status: 200 });
    let result = {};
    if (String(url).includes('/zones?')) result = [{ name: 'example.com' }];
    if (String(url).endsWith('/workers/domains') && (options.method || 'GET') === 'GET') result = [];
    return new Response(JSON.stringify({ success: true, result }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  };

  try {
    delete require.cache[require.resolve('../src/services/CloudflareBootstrapService')];
    const service = require('../src/services/CloudflareBootstrapService');
    const result = await service.deploy({
      accountId: 'a'.repeat(32),
      apiToken: 'token-012345678901234567890123456789',
      originUrl: 'https://origin.example.com',
      apiDomain: 'api.example.com',
      apiWorkerName: 'api-worker',
      adminDomain: 'admin.example.com',
      adminWorkerName: 'admin-worker',
      confirmOverwrite: true
    });

    assert.equal(result.configured, true);
    assert.equal(result.apiTokenConfigured, true);
    assert.equal(JSON.stringify(result).includes('token-012345'), false);
    assert.deepEqual(result.steps.map(step => step.key), ['api_worker', 'api_domain', 'admin_worker', 'admin_domain']);
    assert.equal(calls.filter(call => call.method === 'PUT' && /workers\/scripts\/(api-worker|admin-worker)$/.test(call.url)).length, 2);
    assert.equal(calls.filter(call => call.method === 'PUT' && call.url.endsWith('/secrets')).length, 2);
    assert.equal(calls.filter(call => call.method === 'PUT' && call.url.endsWith('/workers/domains')).length, 2);
    assert.equal(edge.workerName, 'api-worker');
    assert.equal(bootstrap.adminWorkerName, 'admin-worker');
  } finally {
    global.fetch = originalFetch;
  }
});

test('网页向导拒绝未确认覆盖和不属于账号的域名', async () => {
  process.env.NODE_ENV = 'test';
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';
  const service = require('../src/services/CloudflareBootstrapService');
  await assert.rejects(() => service.deploy({ confirmOverwrite: false }), /请先确认/);
  assert.throws(() => service.normalizeInput({
    accountId: 'a'.repeat(32), apiToken: 'token-012345678901234567890123456789',
    originUrl: 'http://origin.example.com', apiDomain: 'api.example.com', apiWorkerName: 'api-worker',
    adminDomain: 'admin.example.com', adminWorkerName: 'admin-worker'
  }), /HTTPS/);
});
