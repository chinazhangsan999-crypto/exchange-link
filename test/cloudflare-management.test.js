'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

test('Cloudflare 管理锁定已有 Worker 的 Account ID 并持久化运行状态', async () => {
  const databasePath = path.join(os.tmpdir(), `webring-cloudflare-${process.pid}-${Date.now()}.db`);
  process.env.DB_PATH = databasePath;
  const model = require('../src/models/CloudflareFrontendModel');
  const database = require('../src/config/database');
  try {
    await model.initializeCloudflareFrontendTables();
    await model.upsertAccount({
      id: 'primary', label: '主账号', accountId: 'a'.repeat(32), workerPrefix: 'public',
      tokenFingerprint: '1234ABCD', tokenStatus: 'valid', activeZones: ['example.com'], isPrimary: true
    });
    const worker = await model.reserveWorker('primary', 'front.example.com', 'example.com');
    await model.updateWorker(worker.id, {
      state: 'ready', domainId: 'domain-123', health: { healthy: true }, deployed: true
    });
    await assert.rejects(() => model.upsertAccount({
      id: 'primary', label: '错误覆盖', accountId: 'b'.repeat(32), workerPrefix: 'other',
      tokenFingerprint: 'EEEEEEEE', tokenStatus: 'valid', activeZones: []
    }), /Account ID 已锁定/);
    const saved = await model.getWorker(worker.id);
    assert.equal(saved.cloudflare_domain_id, 'domain-123');
    assert.ok(saved.last_health_at);
    assert.ok(saved.last_deployed_at);
    await model.upsertAccount({
      id: 'secondary', label: '迁移账号', accountId: 'c'.repeat(32), workerPrefix: 'moved',
      tokenFingerprint: '8765DCBA', tokenStatus: 'valid', activeZones: ['example.com']
    });
    const migration = await model.createMigration({
      hostname: 'front.example.com', sourceAccountProfileId: 'primary',
      targetAccountProfileId: 'secondary', sourceWorkerId: worker.id, migrationType: 'same_domain'
    });
    const target = await model.reserveWorker('secondary', null, null, {
      previousWorkerId: worker.id, migrationState: 'prepared'
    });
    await model.updateMigration(migration.id, 'prepared', { targetWorkerId: target.id });
    await model.promoteMigratedWorker(worker.id, target.id, 'front.example.com', 'domain-new');
    const [retained, promoted] = await Promise.all([model.getWorker(worker.id), model.getWorker(target.id)]);
    assert.equal(retained.hostname, null);
    assert.equal(retained.retained_hostname, 'front.example.com');
    assert.equal(promoted.hostname, 'front.example.com');
    assert.equal(promoted.cloudflare_domain_id, 'domain-new');
    await model.saveCentralState({
      accountId: 'a'.repeat(32), apiWorkerName: 'api-worker', apiDomain: 'api.example.com',
      adminWorkerName: 'admin-worker', adminDomain: 'admin.example.com', originUrl: 'https://origin.example.com',
      tokenFingerprint: '1234ABCD', tokenStatus: 'valid', verified: true, deployed: true
    });
    const central = await model.getCentralState();
    assert.equal(central.token_fingerprint, '1234ABCD');
    assert.ok(central.last_verified_at);

    const CredentialStore = require('../src/services/IntegrationCredentialStore');
    const originalProfiles = CredentialStore.cloudflarePublicFrontendProfiles;
    const originalCentral = CredentialStore.cloudflareApiEdgeConfig;
    const originalSaveProfiles = CredentialStore.saveCloudflarePublicFrontendProfiles;
    const originalFetch = global.fetch;
    let storedProfiles = [];
    CredentialStore.cloudflarePublicFrontendProfiles = () => storedProfiles;
    CredentialStore.cloudflareApiEdgeConfig = () => ({ accountId: 'd'.repeat(32), workerName: 'api-worker', apiToken: 'central-token-012345678901234567890' });
    CredentialStore.saveCloudflarePublicFrontendProfiles = async profiles => { storedProfiles = profiles; };
    global.fetch = async url => new Response(JSON.stringify({ success: true, result: String(url).includes('/zones?') ? [{ name: 'example.com' }] : {} }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    try {
      const service = require('../src/services/CloudflarePublicFrontendService');
      await service.saveProfile({ id: 'central-reuse', label: '复用账号', workerPrefix: 'public', reuseCentralCredential: true }, { skipInitialization: true });
      assert.equal(storedProfiles[0].credentialSource, 'central');
      assert.equal(storedProfiles[0].apiToken, '');
      assert.equal((await service.listProfiles())[0].apiTokenConfigured, true);
    } finally {
      CredentialStore.cloudflarePublicFrontendProfiles = originalProfiles;
      CredentialStore.cloudflareApiEdgeConfig = originalCentral;
      CredentialStore.saveCloudflarePublicFrontendProfiles = originalSaveProfiles;
      global.fetch = originalFetch;
    }
  } finally {
    await database.closeDatabase();
    for (const suffix of ['', '-wal', '-shm']) fs.rmSync(`${databasePath}${suffix}`, { force: true });
  }
});
