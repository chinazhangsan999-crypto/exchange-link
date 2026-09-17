'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

test('多批静态资源共用上传 JWT，并仅在最后一批接收完成 JWT', async () => {
  const databasePath = path.join(os.tmpdir(), `webring-cloudflare-assets-${process.pid}-${Date.now()}.db`);
  process.env.DB_PATH = databasePath;
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';

  const CredentialStore = require('../src/services/IntegrationCredentialStore');
  const model = require('../src/models/CloudflareFrontendModel');
  const database = require('../src/config/database');
  const originalProfiles = CredentialStore.cloudflarePublicFrontendProfiles;
  const originalSaveProfiles = CredentialStore.saveCloudflarePublicFrontendProfiles;
  const originalFetch = global.fetch;
  let storedProfiles = [];
  let uploadCalls = 0;
  let manifestHashes = [];
  let manifestPaths = new Map();
  const uploadAuthorization = [];

  CredentialStore.cloudflarePublicFrontendProfiles = () => storedProfiles;
  CredentialStore.saveCloudflarePublicFrontendProfiles = async profiles => { storedProfiles = profiles; };
  global.fetch = async (url, options = {}) => {
    const target = String(url);
    const response = result => new Response(JSON.stringify({ success: true, result }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
    if (target.endsWith('/user/tokens/verify')) return response({ status: 'active' });
    if (target.includes('/zones?')) return response([{ name: 'example.com' }]);
    if (target.endsWith('/assets-upload-session')) {
      const manifest = JSON.parse(options.body).manifest;
      manifestPaths = new Map(Object.entries(manifest).map(([assetPath, item]) => [item.hash, assetPath]));
      const htmlHash = Object.entries(manifest).find(([assetPath]) => assetPath === '/index.html')?.[1]?.hash;
      const cssHash = Object.entries(manifest).find(([assetPath]) => assetPath.endsWith('.css'))?.[1]?.hash;
      manifestHashes = [htmlHash, cssHash].filter(Boolean);
      assert.ok(manifestHashes.length >= 2);
      return response({ jwt: 'upload-session-token', buckets: [[manifestHashes[0]], [manifestHashes[1]]] });
    }
    if (target.includes('/workers/assets/upload?base64=true')) {
      uploadCalls += 1;
      uploadAuthorization.push(options.headers.Authorization);
      assert.ok(options.body instanceof FormData);
      const expectedHash = manifestHashes[uploadCalls - 1];
      const assetPart = options.body.get(expectedHash);
      assert.ok(assetPart instanceof Blob);
      assert.equal(assetPart.type, manifestPaths.get(expectedHash) === '/index.html' ? 'text/html' : 'text/css');
      return response(uploadCalls === 2 ? { jwt: 'completion-token' } : {});
    }
    if (options.method === 'PUT' && target.includes('/workers/scripts/') && !target.endsWith('/secrets')) {
      const metadata = JSON.parse(await options.body.get('metadata').text());
      assert.equal(metadata.assets.jwt, 'completion-token');
      assert.equal(options.body.get('worker.js').type, 'application/javascript+module');
      assert.ok(metadata.assets.config.run_worker_first.includes('/.well-known/route-health.gif'));
      assert.match(await options.body.get('worker.js').text(), /'\/.well-known\/route-health\.gif'/);
      return response({});
    }
    if (target.endsWith('/secrets')) return response({});
    throw new Error(`未预期的 Cloudflare 请求：${target}`);
  };

  try {
    await model.initializeCloudflareFrontendTables();
    delete require.cache[require.resolve('../src/services/CloudflarePublicFrontendService')];
    const service = require('../src/services/CloudflarePublicFrontendService');
    const profile = await service.saveProfile({
      id: 'cf-test',
      label: '测试账号',
      accountId: 'a'.repeat(32),
      workerPrefix: 'public-test',
      apiToken: 'test-token-012345678901234567890'
    });
    assert.equal(profile.initialization.created, true);
    assert.equal(uploadCalls, 2);
    assert.deepEqual(uploadAuthorization, ['Bearer upload-session-token', 'Bearer upload-session-token']);
  } finally {
    CredentialStore.cloudflarePublicFrontendProfiles = originalProfiles;
    CredentialStore.saveCloudflarePublicFrontendProfiles = originalSaveProfiles;
    global.fetch = originalFetch;
    await database.closeDatabase();
    for (const suffix of ['', '-wal', '-shm']) fs.rmSync(`${databasePath}${suffix}`, { force: true });
  }
});
