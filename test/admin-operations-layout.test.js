'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const adminFile = name => fs.readFileSync(path.join(__dirname, '..', 'public', 'admin', name), 'utf8');

test('外部接入、告警和备份集中到接入与运维且系统设置字段保持不变', () => {
  const operations = adminFile('backup.js');
  const integrations = adminFile('password.js');
  const settings = adminFile('review.js');
  const initializer = adminFile('init.js');
  const html = adminFile('index.html');
  const operationsStyle = adminFile('backup.css');

  assert.match(operations, /接入与运维/);
  assert.match(operations, /导航站告警 Webhook 管理/);
  assert.match(operations, /数据库备份与异地保存/);
  assert.match(operations, /moveAlertSettings/);
  assert.match(operations, /alert-settings-form/);
  assert.match(operations, /alert-bark-fields/);
  assert.match(operations, /alert-health-section/);
  assert.doesNotMatch(operations, /id="alert-settings-form" class="settings-form integration-form"/);
  assert.match(operationsStyle, /\.alert-settings-form\{[^}]*grid-template-columns:minmax\(0,1fr\)/);
  assert.match(operationsStyle, /\.alert-bark-fields\{[^}]*grid-template-columns:repeat\(3,minmax\(0,1fr\)\)/);
  assert.match(operationsStyle, /\.alert-health-section \.webhook-health-grid\{[^}]*grid-template-columns:repeat\(4,minmax\(0,1fr\)\)/);
  assert.match(integrations, /operations-integrations-slot/);
  assert.doesNotMatch(integrations, /querySelector\('#settings'\)/);
  assert.match(initializer, /backup:\s*'operations'/);
  assert.match(initializer, /tab === 'operations'/);
  assert.ok(html.indexOf('/admin/backup.js') < html.indexOf('/admin/password.js'), '接入与运维容器必须先于接入组件加载');

  for (const label of ['站点名称', '永久发布页地址', '防失联官方邮箱', '其他联系方式', '每日首次引导弹窗', '自动通过阈值 N', '本站专属友链地址', '全站 Logo', '站点风控监控参数', '第三方统计设置', '友链 CSV 同步']) {
    assert.match(settings, new RegExp(label));
  }
  assert.doesNotMatch(settings, /payload\.bark_enabled/);
});
