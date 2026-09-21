'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

test('恢复系统可生成、验签、分片并在无 DNS 时发布本地正式版本', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'webring-recovery-'));
  process.env.NODE_ENV = 'test';
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.RECOVERY_CREDENTIAL_FILE = path.join(directory, 'recovery-credentials.json');

  const RecoveryModel = require('../src/models/RecoveryModel');
  const RecoveryService = require('../src/services/RecoveryService');
  const database = require('../src/config/database');

  try {
    await RecoveryModel.initializeRecoveryTables();
    await RecoveryService.updateSettings({
      enabled: 1,
      recovery_email: 'recovery@example.com',
      recovery_publish_url: 'https://publish.example.com/',
      recovery_contact: '@recovery',
      recovery_message: '请通过恢复专用渠道联系。',
      found_message: '该地址已经验签并完成动态图片检测。',
      manifest_valid_days: 90,
      max_domains: 10,
      probe_timeout_ms: 3000,
      probe_concurrency: 3
    });
    await RecoveryModel.createDomain(RecoveryService.validateDomainInput({ title: '线路一', url: 'https://one.example.com', priority: 100, status: 1 }));
    await RecoveryModel.createDomain(RecoveryService.validateDomainInput({ title: '线路二', url: 'https://two.example.net', priority: 90, status: 1 }));

    const draft = await RecoveryService.createDraft();
    assert.equal(draft.envelope.generation, 1);
    assert.equal(draft.envelope.domains.length, 2);
    assert.equal(draft.envelope.fallback.email, 'recovery@example.com');
    assert.equal(draft.envelope.trustedKeys.length, 1);

    const settings = await RecoveryModel.getSettings();
    assert.equal(RecoveryService.verifyEnvelope(draft.envelope, [{ keyId: settings.public_key_id, publicKey: settings.public_key }]), true);

    const chunks = RecoveryService.chunkEnvelope(draft.envelope);
    const rebuilt = RecoveryService.assembleTxt(chunks.parts);
    assert.equal(rebuilt.length, 1);
    assert.deepEqual(rebuilt[0].envelope, draft.envelope);

    const published = await RecoveryService.publishRelease(draft.id);
    assert.equal(published.dnsPublished, 0);
    assert.match(published.warning, /尚未配置 Bootstrap DNS/);

    const manifest = await RecoveryService.getPublicManifest();
    assert.equal(manifest.enabled, true);
    assert.equal(manifest.envelope.generation, 1);
    assert.equal(manifest.publicKeys.length, 1);
    assert.deepEqual(manifest.bootstrapNames, []);

    const browserContext = {
      window: {}, crypto: webcrypto, TextEncoder, TextDecoder,
      atob: value => Buffer.from(value, 'base64').toString('binary'),
      btoa: value => Buffer.from(value, 'binary').toString('base64')
    };
    vm.createContext(browserContext);
    vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'public', 'recovery-crypto.js'), 'utf8'), browserContext);
    assert.equal(await browserContext.window.RecoveryCrypto.verifyEnvelope(manifest.envelope, manifest.publicKeys), true);

    await RecoveryService.generateNextKey();
    await assert.rejects(() => RecoveryService.promoteNextKey(), /尚未安全发布下一代公钥/);
    const transitionDraft = await RecoveryService.createDraft();
    assert.equal(transitionDraft.envelope.trustedKeys.length, 2);
    await RecoveryService.publishRelease(transitionDraft.id);
    await RecoveryService.promoteNextKey();
    const transitionManifest = await RecoveryService.getPublicManifest();
    assert.equal(transitionManifest.publicKeys.length, 2);
    assert.equal(await browserContext.window.RecoveryCrypto.verifyEnvelope(transitionManifest.envelope, transitionManifest.publicKeys), true);

    const rotatedDraft = await RecoveryService.createDraft();
    assert.equal(rotatedDraft.envelope.trustedKeys.length, 1);
    await RecoveryService.publishRelease(rotatedDraft.id);
    const rotatedManifest = await RecoveryService.getPublicManifest();
    assert.equal(rotatedManifest.envelope.generation, 3);
    assert.equal(await browserContext.window.RecoveryCrypto.verifyEnvelope(rotatedManifest.envelope, rotatedManifest.publicKeys), true);
  } finally {
    await database.closeDatabase();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('恢复客户端保持完全独立并仅在导航失败后由 Service Worker 打开', () => {
  const root = path.join(__dirname, '..');
  const serviceWorker = fs.readFileSync(path.join(root, 'public', 'sw.js'), 'utf8');
  const normalClient = fs.readFileSync(path.join(root, 'public', 'recovery-client.js'), 'utf8');
  const recoveryClient = fs.readFileSync(path.join(root, 'public', 'recovery.js'), 'utf8');
  const adminClient = fs.readFileSync(path.join(root, 'public', 'admin', 'recovery.js'), 'utf8');

  assert.match(serviceWorker, /mode === 'navigate'\) return caches\.match\('\/recovery\.html'\)/);
  assert.match(serviceWorker, /'\/\.well-known\/route-health\.gif'/);
  assert.doesNotMatch(normalClient, /doh\.pub|dns\.google|dns\.alidns|cloudflare-dns/);
  assert.match(normalClient, /consecutiveCoreFailures < 2/);
  assert.match(recoveryClient, /doh\.pub/);
  assert.match(recoveryClient, /target = '_blank'/);
  assert.doesNotMatch(recoveryClient, /location\.replace|meta http-equiv|自动跳转/);
  assert.match(adminClient, /不会读取首页弹窗、节点管理或现有防失联设置/);
});
