'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('首次建站无需初始化码，整套部署成功后永久关闭入口', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-bootstrap-access-'));
  process.env.NODE_ENV = 'test';
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.CLOUDFLARE_BOOTSTRAP_STATE_FILE = path.join(directory, 'bootstrap-state.json');
  process.env.CLOUDFLARE_BOOTSTRAP_TOKEN_FILE = path.join(directory, 'bootstrap-token.txt');
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';

  const CredentialStore = require('../src/services/IntegrationCredentialStore');
  CredentialStore.cloudflareApiEdgeConfig = () => ({ accountId: '', workerName: '', apiToken: '' });
  const access = require('../src/services/CloudflareBootstrapAccessService');
  const bootstrap = require('../src/services/CloudflareBootstrapService');
  const publicFrontend = require('../src/services/CloudflarePublicFrontendService');
  const apiEdge = require('../src/services/CloudflareApiEdgeService');
  const FrontendOriginModel = require('../src/models/FrontendOriginModel');
  bootstrap.deploy = async input => ({
    adminDomain: input.adminDomain,
    note: '测试部署完成',
    steps: []
  });
  let savedProfile = null;
  publicFrontend.saveProfile = async (input, options) => {
    savedProfile = { input, options };
    return { id: input.id };
  };
  publicFrontend.createDedicatedFrontend = async hostname => ({
    id: 1,
    hostname,
    workerName: 'webring-public-001',
    zone: 'example.com',
    profileId: 'cf-first',
    domainId: 'domain-1'
  });
  publicFrontend.checkHealth = async () => ({ healthy: true, pageStatus: 200, apiStatus: 200 });
  publicFrontend.finalizeDedicatedFrontend = async () => undefined;
  publicFrontend.rollbackDedicatedFrontend = async () => undefined;
  FrontendOriginModel.listAllOrigins = async () => [];
  FrontendOriginModel.replaceOrigins = async items => ({ count: items.length });
  apiEdge.syncAllowedOrigins = async items => ({ synchronized: true, origins: items.map(item => item.origin) });

  await fs.writeFile(access.TOKEN_FILE, 'legacy-token-must-be-removed\n');
  const initial = await access.initialize();
  assert.equal(initial.available, true);
  await assert.rejects(() => fs.access(access.TOKEN_FILE));
  CredentialStore.cloudflareApiEdgeConfig = () => ({
    accountId: '0123456789abcdef0123456789abcdef',
    workerName: 'webring-api-test',
    apiToken: 'saved-after-partial-deployment'
  });
  assert.equal((await access.publicStatus()).available, true);

  const app = require('../src/app');
  const database = require('../src/config/database');
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${baseUrl}/setup`)).status, 200);
    const success = await fetch(`${baseUrl}/api/setup/deploy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId: '0123456789abcdef0123456789abcdef',
        apiToken: 'test-cloudflare-api-token-0123456789',
        adminDomain: 'admin.example.com',
        frontendHostname: 'www.example.com',
        sameCloudflareAccount: true
      })
    });
    assert.equal(success.status, 200);
    const payload = await success.json();
    assert.equal(payload.data.frontend.service, 'webring-public-001');
    assert.equal(savedProfile.input.accountId, '0123456789abcdef0123456789abcdef');
    assert.equal(savedProfile.options.skipInitialization, true);
    assert.equal((await fetch(`${baseUrl}/setup`)).status, 404);
    await assert.rejects(() => fs.access(access.TOKEN_FILE));
  } finally {
    await new Promise(resolve => server.close(resolve));
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
