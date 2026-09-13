'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('入站后站内浏览独立累计，且不改变有效入站统计口径', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-partner-pages-'));
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';

  const database = require('../src/config/database');
  const SystemModel = require('../src/models/SystemModel');
  const PartnerModel = require('../src/models/PartnerModel');
  const LogModel = require('../src/models/LogModel');
  const PartnerPageViewModel = require('../src/models/PartnerPageViewModel');
  const PartnerPageViewService = require('../src/services/PartnerPageViewService');

  try {
    await SystemModel.initializeDatabase();
    await PartnerPageViewModel.initializePartnerPageViewTable();
    const partner = await database.run(`INSERT INTO partners(name, domain, url, category, is_approved)
      VALUES ('测试站点', 'example.com', 'https://example.com', '默认', 1)`);

    PartnerPageViewService.recordConfirmedEntry({ partnerId: partner.id, visitId: 'visit-one' });
    PartnerPageViewService.recordPageView({ partnerId: partner.id, visitId: 'visit-one' });
    PartnerPageViewService.recordPageView({ partnerId: partner.id, visitId: 'visit-one' });
    PartnerPageViewService.recordConfirmedEntry({ partnerId: partner.id, visitId: 'visit-two' });
    await PartnerPageViewService.flush();

    const summary = await PartnerPageViewModel.getRecentSummary(partner.id);
    assert.equal(summary.page_pv, 4);
    assert.equal(summary.post_entry_page_pv, 2, '只统计入站后打开的页面，不将入口心跳计作浏览');
    assert.equal(summary.attributed_sessions, 2);
    assert.equal(summary.continued_sessions, 1);

    const analytics = await LogModel.getPartnerAnalytics(partner.id, { includeClients: false });
    assert.equal(analytics.summary.pv, 0, '不会把站内浏览写入有效入站心跳表');
    assert.equal(analytics.partnerPageViews.page_pv, 4);
    assert.equal(analytics.partnerPageViews.post_entry_page_pv, 2);
    assert.equal(analytics.partnerPageViewVisits.length, 2);

    const beforeScope = await PartnerModel.getPingInspectionScope('manual');
    await database.run(`INSERT INTO partners(name, domain, url, category, is_approved, is_internal)
      VALUES ('内部节点', 'node.example', 'https://node.example', '默认', 1, 1)`);
    await database.run(`INSERT INTO partners(name, domain, url, category, is_approved, ping_exempt)
      VALUES ('Ping免检', 'exempt.example', 'https://exempt.example', '默认', 1, 1)`);
    const scope = await PartnerModel.getPingInspectionScope('manual');
    assert.equal(Number(scope.external_target_total), Number(beforeScope.external_target_total));
    assert.equal(Number(scope.internal_skipped), Number(beforeScope.internal_skipped) + 1);
    assert.equal(Number(scope.ping_exempt_skipped), Number(beforeScope.ping_exempt_skipped) + 1);
  } finally {
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
