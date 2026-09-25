'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

test('ClouDNS 免费套餐错误会转换为明确的中文付费提示', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(JSON.stringify({
    status: 'Failed',
    statusDescription: "You don't have access to the HTTP API. Check your plan."
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });

  try {
    const DnsPublisherService = require('../src/services/DnsPublisherService');
    await assert.rejects(
      DnsPublisherService.verifyChannel('cloudns', {
        authType: 'auth-id', authId: '68854', authPassword: 'test-password'
      }),
      /ClouDNS 当前套餐不包含 HTTP API，请升级到 Premium DNS 等付费套餐后重试/
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test('恢复系统可生成、验签、分片并在无 DNS 时发布本地正式版本', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'webring-recovery-'));
  process.env.NODE_ENV = 'test';
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.RECOVERY_CREDENTIAL_FILE = path.join(directory, 'recovery-credentials.json');

  const RecoveryModel = require('../src/models/RecoveryModel');
  const RecoveryService = require('../src/services/RecoveryService');
  const CloudflareFrontendModel = require('../src/models/CloudflareFrontendModel');
  const FrontendOriginModel = require('../src/models/FrontendOriginModel');
  const database = require('../src/config/database');

  try {
    await RecoveryModel.initializeRecoveryTables();
    await CloudflareFrontendModel.initializeCloudflareFrontendTables();
    await FrontendOriginModel.initializeFrontendOriginTable();
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
    const cloudflareChannel = await RecoveryService.createDnsChannel({
      label: 'Cloudflare 账号 A', providerId: 'cloudflare',
      accountId: '0123456789abcdef0123456789abcdef', apiToken: 'cf-token-abcdefghijklmnopqrstuvwxyz', status: 1
    });
    const cloudflareChannelB = await RecoveryService.createDnsChannel({
      label: 'Cloudflare 账号 B', providerId: 'cloudflare',
      accountId: 'fedcba9876543210fedcba9876543210', apiToken: 'cf-token-b-abcdefghijklmnopqrstuvwxyz', status: 1
    });
    const deSecChannel = await RecoveryService.createDnsChannel({
      label: 'deSEC 账号', providerId: 'desec', apiToken: 'desec-token-abcdefghijklmnopqrstuvwxyz', status: 1
    });
    const cloudnsChannel = await RecoveryService.createDnsChannel({
      label: 'ClouDNS 账号', providerId: 'cloudns', authType: 'sub-auth-id', authId: '12345', authPassword: 'cloudns-secret', status: 1
    });
    const route53Channel = await RecoveryService.createDnsChannel({
      label: 'Route 53 账号', providerId: 'route53', accessKeyId: 'AKIA0123456789ABCDEF',
      secretAccessKey: 'route53-secret-access-key-abcdefghijklmnopqrstuvwxyz', status: 1
    });
    const dnspodChannel = await RecoveryService.createDnsChannel({
      label: 'DNSPod 账号', providerId: 'dnspod', secretId: 'AKID0123456789ABCDEFGHIJKLMNOP', secretKey: 'dnspod-secret-key-abcdefghijklmnopqrstuvwxyz', status: 1
    });
    const aliyunChannel = await RecoveryService.createDnsChannel({
      label: '阿里云账号', providerId: 'aliyun', accessKeyId: 'LTAI5t0123456789abcd', accessKeySecret: 'aliyun-secret-key-abcdefghijklmnopqrstuvwxyz', status: 1
    });
    const baiduChannel = await RecoveryService.createDnsChannel({
      label: '百度云账号', providerId: 'baidu', accessKeyId: 'bce-access-key-0123456789', secretAccessKey: 'baidu-secret-key-abcdefghijklmnopqrstuvwxyz', status: 1
    });
    const volcengineChannel = await RecoveryService.createDnsChannel({
      label: '火山引擎账号', providerId: 'volcengine', accessKeyId: 'AKLT0123456789ABCDEF', secretAccessKey: 'volcengine-secret-key-abcdefghijklmnopqrstuvwxyz', region: 'cn-beijing', status: 1
    });
    assert.notEqual(cloudflareChannel.id, cloudflareChannelB.id);
    assert.equal(cloudnsChannel.auth_type, 'sub-auth-id');
    assert.deepEqual([cloudflareChannel, cloudflareChannelB, deSecChannel, cloudnsChannel, route53Channel, dnspodChannel, aliyunChannel, baiduChannel, volcengineChannel].map(item => item.configured), [true, true, true, true, true, true, true, true, true]);
    const channelOverview = await RecoveryService.overview();
    assert.equal(channelOverview.dnsChannels.length, 9);
    assert.equal(volcengineChannel.region, 'cn-beijing');
    for (const providerId of ['dnspod', 'aliyun', 'baidu', 'volcengine']) {
      const provider = channelOverview.dnsProviders.find(item => item.id === providerId);
      assert.equal(provider.automatic_publish, true);
      assert.equal(provider.portable_record_bytes, 240);
    }
    assert.doesNotMatch(JSON.stringify(channelOverview.dnsChannels), /cf-token|desec-token|cloudns-secret|route53-secret|dnspod-secret|aliyun-secret|baidu-secret|volcengine-secret/);
    assert.deepEqual(channelOverview.txtPolicy, {
      portableBytes: 240,
      maxEncodedBytes: 4096,
      maxPartsPerRole: 50,
      legacyDataBytes: 180
    });
    const publishGroup = await RecoveryService.createBootstrapGroup({
      label: '主力双分片与 R1 兼容',
      compatibilityMode: 'AB_R1',
      domains: [
        { title: 'DNS 线路一', url: 'https://dns-one.example.com', priority: 80, status: 1 },
        { title: 'DNS 线路二', url: 'https://dns-two.example.net', priority: 70, status: 0 }
      ],
      targets: [
        {
          label: 'Cloudflare A', shareRole: 'A', publishMode: 'automatic',
          dnsChannelId: cloudflareChannelB.id, zoneName: 'example.com',
          providerZoneId: 'cf-zone-id', recordName: '_recovery-a.example.com',
          requiredTarget: 1, status: 0
        },
        {
          label: 'deSEC B', shareRole: 'B', publishMode: 'automatic',
          dnsChannelId: deSecChannel.id, zoneName: 'example.net',
          providerZoneId: 'example.net', recordName: '_recovery-b.example.net',
          requiredTarget: 1, status: 0
        },
        {
          label: 'HE R1', shareRole: 'LEGACY', publishMode: 'manual', providerId: 'he',
          zoneName: 'example.org', recordName: '_recovery.example.org', status: 0
        }
      ]
    });
    const groupedOverview = await RecoveryService.overview();
    assert.equal(groupedOverview.bootstrapGroups.some(item => item.id === publishGroup.id), true);
    const groupedRecords = groupedOverview.bootstraps.filter(item => item.group_id === publishGroup.id);
    assert.deepEqual(groupedRecords.map(item => item.share_role), ['A', 'B', 'LEGACY']);
    assert.deepEqual(groupedRecords.map(item => item.publish_mode), ['automatic', 'automatic', 'manual']);
    assert.deepEqual(groupedRecords.map(item => item.required_target), [1, 1, 0]);
    assert.equal(groupedOverview.bootstrapGroupDomains.filter(item => item.group_id === publishGroup.id).length, 2);
    const r1Group = await RecoveryService.createBootstrapGroup({
      label: '三层线路自动编排测试', compatibilityMode: 'R1',
      domains: [{ title: 'R1 入口', url: 'https://r1.example.org', priority: 10, status: 1 }],
      targets: [{
        label: 'R1 TXT', shareRole: 'LEGACY', publishMode: 'manual', providerId: 'he',
        zoneName: 'example.org', recordName: '_recovery-r1.example.org', requiredTarget: 1, status: 1
      }]
    });
    const r1Preview = await RecoveryService.buildLookupRoutePlan(r1Group.id, { applyMode: 'fill_missing' });
    assert.equal(r1Preview.validation.valid, true);
    assert.equal(r1Preview.summary.create, 8);
    assert.deepEqual(r1Preview.tiers.map(item => [item.priorityGroup, item.expected, item.complete]), [[1, 2, true], [2, 3, true], [3, 3, true]]);
    await RecoveryService.applyLookupRoutePlan(r1Group.id, { applyMode: 'fill_missing', configurationRevision: r1Preview.configurationRevision });
    const r1Idempotent = await RecoveryService.buildLookupRoutePlan(r1Group.id, { applyMode: 'fill_missing' });
    assert.deepEqual(r1Idempotent.summary, { create: 0, update: 0, keep: 8, remove: 0, conflict: 0, total: 8 });
    const r1Routes = (await RecoveryModel.listLookupRoutes()).filter(item => Number(item.group_id) === Number(r1Group.id));
    await database.run('UPDATE recovery_lookup_routes SET priority_group=4 WHERE id=?', [r1Routes[0].id]);
    const protectedPreview = await RecoveryService.buildLookupRoutePlan(r1Group.id, { applyMode: 'fill_missing' });
    assert.equal(protectedPreview.validation.valid, false);
    assert.equal(protectedPreview.summary.conflict, 1);
    const syncPreview = await RecoveryService.buildLookupRoutePlan(r1Group.id, { applyMode: 'sync_template' });
    assert.equal(syncPreview.validation.valid, true);
    assert.equal(syncPreview.summary.update, 1);
    await RecoveryService.applyLookupRoutePlan(r1Group.id, { applyMode: 'sync_template', configurationRevision: syncPreview.configurationRevision });
    const automatedOverview = await RecoveryService.overview();
    assert.equal(automatedOverview.lookupRouteHealth[r1Group.id].structuralStatus, 'complete');
    assert.equal(automatedOverview.lookupRouteHealth[r1Group.id].routeCount, 8);
    await RecoveryService.deleteBootstrapGroup(r1Group.id);
    assert.equal((await RecoveryModel.listDomains()).length, 0);
    await assert.rejects(() => RecoveryService.createDraft(), /至少需要一条已启用的恢复线路/);
    await assert.rejects(() => RecoveryService.createBootstrapGroup({
      label: '错误的同权威组合', compatibilityMode: 'AB',
      domains: [{ title: 'DNS 错误线路', url: 'https://dns-bad.example.com', priority: 0, status: 1 }],
      targets: [
        { shareRole: 'A', publishMode: 'automatic', dnsChannelId: cloudflareChannelB.id, zoneName: 'example.com', recordName: '_bad-a.example.com', status: 0 },
        { shareRole: 'B', publishMode: 'automatic', dnsChannelId: cloudflareChannelB.id, zoneName: 'example.com', recordName: '_bad-b.example.com', status: 0 }
      ]
    }), /A 与 B 必须至少形成一组不同权威 DNS/);
    const automaticInput = await RecoveryService.validateBootstrapConfiguration(RecoveryService.validateBootstrapInput({
      label: '临时自动发布', recordName: '_recovery.example.com', zoneName: 'example.com',
      providerId: 'cloudflare', publishMode: 'automatic', dnsChannelId: cloudflareChannel.id, status: 1
    }));
    const automaticRecord = await RecoveryModel.createBootstrapRecord(automaticInput);
    await assert.rejects(() => RecoveryService.deleteDnsChannel(cloudflareChannel.id), /仍被 Bootstrap DNS 使用/);
    await RecoveryModel.deleteBootstrapRecord(automaticRecord.id);
    await RecoveryService.deleteDnsChannel(cloudflareChannel.id);
    assert.equal((await RecoveryModel.listDnsChannels()).length, 8);
    await assert.rejects(() => RecoveryService.validateBootstrapConfiguration(RecoveryService.validateBootstrapInput({
      label: '服务商不匹配', recordName: '_recovery.example.com', zoneName: 'example.com',
      providerId: 'desec', publishMode: 'automatic', dnsChannelId: cloudflareChannelB.id, status: 1
    })), /服务商不匹配/);
    await RecoveryModel.createDomain(RecoveryService.validateDomainInput({ title: '线路一', url: 'https://one.example.com', priority: 100, status: 1 }));
    await RecoveryModel.createDomain(RecoveryService.validateDomainInput({ title: '线路二', url: 'https://two.example.net', priority: 90, status: 1 }));

    const draft = await RecoveryService.createDraft();
    assert.equal(draft.envelope.generation, 1);
    assert.equal(draft.envelope.domains.length, 2);
    assert.equal(draft.envelope.schema, 3);
    assert.equal(draft.envelope.fallback, undefined);
    assert.equal(draft.envelope.trustedKeys.length, 1);
    assert.equal(draft.dnsEnvelopes.length, 1);
    assert.equal(draft.dnsEnvelopes[0].groupId, publishGroup.id);
    assert.deepEqual(draft.dnsEnvelopes[0].envelope.domains.map(item => item.url), ['https://dns-one.example.com']);
    assert.deepEqual(draft.envelope.domains.map(item => item.url), ['https://one.example.com', 'https://two.example.net']);
    assert.equal(draft.dnsEnvelopes[0].envelope.domains.some(item => item.url === 'https://one.example.com'), false);
    await RecoveryService.deleteBootstrapGroup(publishGroup.id);
    assert.equal((await RecoveryModel.listBootstrapRecords()).some(item => item.group_id === publishGroup.id), false);

    const settings = await RecoveryModel.getSettings();
    assert.equal(RecoveryService.verifyEnvelope(draft.envelope, [{ keyId: settings.public_key_id, publicKey: settings.public_key }]), true);

    const chunks = RecoveryService.chunkEnvelope(draft.envelope);
    assert.ok(chunks.parts.every(value => Buffer.byteLength(value, 'utf8') <= 240));
    assert.throws(() => RecoveryService.assertPortableTxt(['x'.repeat(241)], 240), /超过托管商安全上限/);
    const rebuilt = RecoveryService.assembleTxt(chunks.parts);
    assert.equal(rebuilt.length, 1);
    assert.deepEqual(rebuilt[0].envelope, draft.envelope);
    const shards = RecoveryService.shardEnvelope(draft.envelope);
    assert.ok(shards.A.parts.every(value => Buffer.byteLength(value, 'utf8') <= 240));
    assert.ok(shards.B.parts.every(value => Buffer.byteLength(value, 'utf8') <= 240));
    assert.equal(RecoveryService.combineShards(RecoveryService.assembleShardedTxt(shards.A.parts)).length, 0);
    const combined = RecoveryService.combineShards(RecoveryService.assembleShardedTxt([...shards.A.parts, ...shards.B.parts]));
    assert.equal(combined.length, 1);
    assert.deepEqual(combined[0].envelope, draft.envelope);
    const stableShards = RecoveryService.shardEnvelope(draft.envelope, 240, 'test-release-secret');
    const stableShardsAgain = RecoveryService.shardEnvelope(draft.envelope, 240, 'test-release-secret');
    assert.deepEqual(stableShards, stableShardsAgain);
    const damagedB = [...stableShards.B.parts];
    damagedB[0] = damagedB[0].replace(/data=(.)/, (_match, first) => `data=${first === 'X' ? 'Y' : 'X'}`);
    assert.equal(RecoveryService.combineShards(RecoveryService.assembleShardedTxt([...stableShards.A.parts, ...damagedB])).length, 0);

    const published = await RecoveryService.publishRelease(draft.id);
    assert.equal(published.dnsPublished, 0);
    assert.match(published.warning, /尚未配置 Bootstrap DNS/);

    const manifest = await RecoveryService.getPublicManifest();
    assert.equal(manifest.enabled, true);
    assert.equal(manifest.envelope.generation, 1);
    assert.equal(manifest.publicKeys.length, 1);
    assert.equal(manifest.localFallback.email, 'recovery@example.com');
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

    const second = await RecoveryModel.createProfile({ name: '海外恢复方案', code: 'global' });
    await RecoveryService.updateSettings({
      enabled: 1, recovery_email: 'global@example.com', manifest_valid_days: 60,
      max_domains: 10, probe_timeout_ms: 2500, probe_concurrency: 2
    }, second.id);
    await RecoveryModel.createDomain(RecoveryService.validateDomainInput({ title: '海外线路', url: 'https://global.example.org', priority: 10, status: 1 }), second.id);
    const txtA = await RecoveryModel.createBootstrapRecord(RecoveryService.validateBootstrapInput({ label: '国内 TXT', recordName: '_recover.cn.example.org', zoneName: 'example.org', status: 1 }), second.id);
    const txtB = await RecoveryModel.createBootstrapRecord(RecoveryService.validateBootstrapInput({ label: '全球 TXT', recordName: '_recover.global.example.org', zoneName: 'example.org', status: 1 }), second.id);
    await RecoveryModel.createLookupRoute(RecoveryService.validateLookupRouteInput({ resolverId: 'dnspod', bootstrapId: txtA.id, priorityGroup: 1, timeoutMs: 1800, status: 1 }), second.id);
    await RecoveryModel.createLookupRoute(RecoveryService.validateLookupRouteInput({ resolverId: 'google', bootstrapId: txtB.id, priorityGroup: 2, timeoutMs: 2600, status: 1 }), second.id);
    const secondDraft = await RecoveryService.createDraft({ profileId: second.id });
    assert.equal(secondDraft.envelope.schema, 3);
    assert.equal(secondDraft.envelope.lookupRoutes, undefined);
    await RecoveryModel.deleteBootstrapRecord(txtA.id, second.id);
    await RecoveryModel.deleteBootstrapRecord(txtB.id, second.id);
    await RecoveryService.publishRelease(secondDraft.id, second.id);

    await database.run(`INSERT INTO cloudflare_frontend_accounts(id,label,account_id,worker_prefix)
      VALUES ('test','测试账号','0123456789abcdef0123456789abcdef','test-public')`);
    await database.run(`INSERT INTO cloudflare_frontend_workers(account_profile_id,worker_name,hostname,zone_name,state,recovery_profile_id)
      VALUES ('test','test-public-001','global.example.test','example.test','ready',?)`, [second.id]);
    await FrontendOriginModel.replaceOrigins([
      { origin: 'https://houtai.example.test', enabled: true },
      { origin: 'https://global.example.test', enabled: true }
    ]);
    const overview = await RecoveryService.overview(second.id);
    assert.equal(overview.publicPreviewOrigin, 'https://global.example.test');
    const boundManifest = await RecoveryService.getPublicManifest('https://global.example.test');
    assert.equal(boundManifest.enabled, true);
    assert.equal(boundManifest.envelope.project, second.project_id);
    assert.equal(boundManifest.localFallback.email, 'global@example.com');
    assert.deepEqual(boundManifest.lookupRoutes, []);
    const unboundManifest = await RecoveryService.getPublicManifest('https://unbound.example.test');
    assert.equal(unboundManifest.enabled, false);
    assert.equal(unboundManifest.reason, 'frontend_unbound');
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
  const reviewClient = fs.readFileSync(path.join(root, 'public', 'admin', 'review.js'), 'utf8');
  const frontendProxy = fs.readFileSync(path.join(root, 'src', 'middlewares', 'frontendProxy.js'), 'utf8');

  assert.match(serviceWorker, /mode === 'navigate'\) return caches\.match\('\/recovery\.html'\)/);
  assert.match(serviceWorker, /'\/\.well-known\/route-health\.gif'/);
  assert.doesNotMatch(normalClient, /doh\.pub|dns\.google|dns\.alidns|cloudflare-dns/);
  assert.match(normalClient, /consecutiveCoreFailures < 2/);
  assert.match(recoveryClient, /doh\.pub/);
  assert.match(recoveryClient, /lookupRoutes/);
  assert.match(recoveryClient, /application\/dns-message/);
  assert.match(recoveryClient, /priority/);
  assert.match(recoveryClient, /target = '_blank'/);
  assert.doesNotMatch(recoveryClient, /location\.replace|meta http-equiv|自动跳转/);
  assert.match(adminClient, /不会读取首页弹窗、节点管理或现有防失联设置/);
  assert.match(adminClient, /DNS \/ Bootstrap 查询线路/);
  assert.match(adminClient, /自动配置全部线路/);
  assert.match(adminClient, /中国大陆主力/);
  assert.match(adminClient, /全球主力/);
  assert.match(adminClient, /扩展容灾/);
  assert.match(adminClient, /id="recovery-route-form"/);
  assert.match(adminClient, /添加查询线路/);
  assert.match(adminClient, /bootstrapGroups = \[\]/);
  assert.match(adminClient, /系统统一采用每条.*字节安全上限/);
  assert.match(adminClient, /直接恢复线路（浏览器本地保存）/);
  assert.match(adminClient, /DNS TXT 候选域名/);
  assert.match(adminClient, /data-recovery-action="add-group-domain"/);
  assert.match(adminClient, /bootstrapGroupDomains = \[\]/);
  assert.match(adminClient, /domains: collectGroupDomains\(\)/);
  assert.doesNotMatch(adminClient, /add-domain-from-group|returnToGroupFromDomain|renderGroupDomainPreview/);
  assert.match(recoveryClient, /highestDnsGeneration/);
  assert.match(recoveryClient, /dnsEnvelopes/);
  assert.match(reviewClient, /recoveryProfileId/);
  assert.match(reviewClient, /每个独立前台必须绑定一套已启用且已发布的恢复方案/);
  assert.match(frontendProxy, /'\/api\/recovery\/'/);
});
