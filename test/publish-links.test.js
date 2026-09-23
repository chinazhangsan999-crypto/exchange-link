'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('中央永久发布页自动替换且不覆盖本站自定义项', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-publish-links-'));
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';
  process.env.INITIAL_ADMIN_PASSWORD = 'LocalTestPassword123';

  const database = require('../src/config/database');
  const SystemModel = require('../src/models/SystemModel');
  const AdsModel = require('../src/models/AdsModel');
  const MirrorModel = require('../src/models/MirrorModel');
  const PublishLinkModel = require('../src/models/PublishLinkModel');
  const { createWebringConfigApplier } = require('../packages/site-agent/webring-adapter');

  try {
    await SystemModel.initializeDatabase();
    await AdsModel.initializeAdsTable();
    await MirrorModel.initializeMirrorsTable();
    await SystemModel.upsertConfig('publish_url', 'https://local.example/');
    const adapter = createWebringConfigApplier(database);
    await adapter.initialize();

    const snapshot = {
      revision: '1-1-1', nodes: [], ads: [], ad_policies: [],
      publish: {
        permanent_url: 'https://central.example/', github_pages_url: 'https://github.example/',
        pages: [
          { id: 'cloudflare', label: '中央永久页', url: 'https://central.example/', enabled: true, sort_order: 10, sort_weight: 500 },
          { id: 'duplicate-local', label: '中央同址页', url: 'https://local.example/', enabled: true, sort_order: 20, sort_weight: 900 }
        ]
      }
    };
    await adapter.applyConfig(snapshot);

    const allLinks = await PublishLinkModel.listAll();
    assert.equal(allLinks.filter(item => item.source === 'control_center').length, 2);
    assert.equal(allLinks.filter(item => item.source === 'local').length, 1);
    const publicLinks = await PublishLinkModel.listPublic();
    assert.deepEqual(publicLinks.map(item => item.url), ['https://central.example/', 'https://local.example/']);
    assert.equal(publicLinks[1].source, 'local');

    await PublishLinkModel.replaceLocal([
      { label: '本站高权重', url: 'https://local.example/', enabled: true, sort_weight: 800 },
      { label: '本站低权重', url: 'https://local-low.example/', enabled: true, sort_weight: 100 }
    ]);
    assert.deepEqual((await PublishLinkModel.listPublic()).map(item => item.url), [
      'https://local.example/', 'https://central.example/', 'https://local-low.example/'
    ]);

    await adapter.applyConfig({ ...snapshot, revision: '1-1-2', publish: { permanent_url: '', github_pages_url: '', pages: [] } });
    assert.deepEqual((await PublishLinkModel.listAll()).map(item => item.source), ['local', 'local']);
  } finally {
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('首页引导弹窗不再加载或展示备用镜像', async () => {
  const [html, script] = await Promise.all([
    fs.readFile(path.join(__dirname, '..', 'public', 'index.html'), 'utf8'),
    fs.readFile(path.join(__dirname, '..', 'public', 'script.js'), 'utf8')
  ]);
  assert.doesNotMatch(html, /最新备用镜像|modalMirrorsSection|modalMirrorsContainer/);
  assert.doesNotMatch(script, /fetch\(['"]\/api\/mirrors/);
  assert.match(script, /publish_pages/);
});
