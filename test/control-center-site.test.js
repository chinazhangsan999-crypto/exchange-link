'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('总后台接管节点且广告策略不覆盖本地广告数据', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-control-'));
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';
  process.env.INITIAL_ADMIN_PASSWORD = 'LocalTestPassword123';
  process.env.CONTROL_CENTER_ENABLED = '1';
  process.env.CONTROL_CENTER_URL = 'https://control.example.com';
  process.env.CONTROL_CENTER_SITE_CREDENTIAL = '1.abcdefghijklmnopqrstuvwxyzABCDEF';

  const database = require('../src/config/database');
  const SystemModel = require('../src/models/SystemModel');
  const AdModel = require('../src/models/AdModel');
  const MirrorModel = require('../src/models/MirrorModel');
  const ControlCenterAgentService = require('../src/services/ControlCenterAgentService');
  const AdminController = require('../src/controllers/AdminController');

  try {
    await SystemModel.initializeDatabase();
    await AdModel.initializeAdsTable();
    await MirrorModel.initializeMirrorsTable();
    await ControlCenterAgentService.initialize();

    await database.run(`INSERT INTO ads(type,title,ad_type,ad_position,platform,target_url,image_url,sort_order,status,managed_by,namespace)
      VALUES('banner','Local','normal','banner','all','https://local.example','https://local.example/a.png',90,1,'local','local:1')`);
    await database.run(`INSERT INTO ads(type,title,ad_type,ad_position,platform,target_url,image_url,sort_order,status,managed_by,central_id,namespace)
      VALUES('banner','Central','normal','banner','all','https://central.example','https://central.example/a.png',10,1,'central','1','central:1')`);
    await database.run(`INSERT INTO site_configs(key,value) VALUES('central_ad_policy:banner','central_only')
      ON CONFLICT(key) DO UPDATE SET value='central_only'`);

    assert.deepEqual((await AdModel.getActiveAds()).map(item => item.title), ['Central']);
    assert.deepEqual((await AdModel.listLocalAds()).map(item => item.title), ['Local']);

    const response = () => ({
      statusCode: 200,
      body: null,
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; }
    });
    const syncResponse = response();
    await AdminController.syncAdsMatrix({}, syncResponse);
    assert.equal(syncResponse.statusCode, 403);
    assert.match(syncResponse.body.msg, /总后台统一管理/);

    const exportResponse = response();
    await AdminController.exportMatrix({ params: { type: 'ads' } }, exportResponse);
    assert.equal(exportResponse.statusCode, 403);
    assert.match(exportResponse.body.msg, /仅提供友链 CSV 备份/);
  } finally {
    ControlCenterAgentService.stop();
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('总后台接管后导航站 CSV 区域只保留友链操作', async () => {
  const reviewSource = await fs.readFile(path.join(__dirname, '..', 'public', 'admin', 'review.js'), 'utf8');
  const appSource = await fs.readFile(path.join(__dirname, '..', 'public', 'admin', 'app.js'), 'utf8');

  assert.match(reviewSource, /友链 CSV 同步/);
  assert.match(reviewSource, /id="save-matrix-urls"/);
  assert.match(reviewSource, /id="sync-matrix-partners"/);
  assert.match(reviewSource, /id="download-matrix-partners"/);
  assert.doesNotMatch(reviewSource, /广告矩阵表 CSV 直链/);
  assert.doesNotMatch(reviewSource, /data-sync-type="ads"/);
  assert.doesNotMatch(reviewSource, /data-export-type="ads"/);
  assert.doesNotMatch(appSource, /runMatrixSync\(\['partners', 'ads'/);
});
