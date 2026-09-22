'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '..');

test('机器人识别能力、质量、策略版本和安全设置保留在统一后台', () => {
  const html = fs.readFileSync(path.join(root, 'public', 'admin.html'), 'utf8');
  const script = fs.readFileSync(path.join(root, 'public', 'admin.js'), 'utf8');
  const routes = fs.readFileSync(path.join(root, 'src', 'routes', 'index.js'), 'utf8');
  for (const tab of ['connections', 'suspects', 'detection', 'quality', 'rules', 'alerts', 'maintenance', 'security', 'audits']) {
    assert.match(html, new RegExp(`data-tab="${tab}"`));
  }
  assert.match(html, /detection-body/);
  assert.match(html, /quality-pass-rate/);
  assert.match(html, /policies-body/);
  assert.match(html, /security-sessions-body/);
  assert.match(html, /revoke-all-sessions/);
  assert.match(script, /loadDetection/);
  assert.match(script, /loadQuality/);
  assert.match(script, /loadSecurity/);
  assert.match(routes, /detection\/capabilities/);
  assert.match(routes, /security\/credentials/);
  assert.match(routes, /sessions\/revoke-others/);
  assert.match(routes, /sessions\/revoke-all/);
});

test('数据库迁移持久化后台账号、会话、规则修订和新增参考组件', () => {
  const migration = fs.readFileSync(path.join(root, 'migrations', '008_detection_security.sql'), 'utf8');
  assert.match(migration, /CREATE TABLE IF NOT EXISTS admin_credentials/);
  assert.match(migration, /CREATE TABLE IF NOT EXISTS admin_sessions/);
  assert.match(migration, /CREATE TABLE IF NOT EXISTS signal_rule_revisions/);
  assert.match(migration, /chaitin\/SafeLine/);
  assert.match(migration, /bunkerity\/bunkerweb/);
});

test('导航站把关键正负机器人信号接入风险中心', () => {
  const projectRoot = path.join(root, '..');
  const publicController = fs.readFileSync(path.join(projectRoot, 'src', 'controllers', 'PublicController.js'), 'utf8');
  const visitorRisk = fs.readFileSync(path.join(projectRoot, 'src', 'services', 'VisitorRiskService.js'), 'utf8');
  const readAccess = fs.readFileSync(path.join(projectRoot, 'src', 'middlewares', 'readAccess.js'), 'utf8');
  const concurrency = fs.readFileSync(path.join(projectRoot, 'src', 'middlewares', 'readConcurrency.js'), 'utf8');
  for (const signal of ['challenge_failed', 'normal_dwell', 'outbound_interaction']) {
    assert.match(publicController, new RegExp(signal));
  }
  assert.match(visitorRisk, /known_ai_crawler/);
  assert.match(visitorRisk, /missing_fetch_metadata/);
  assert.match(readAccess, /token_replay/);
  assert.match(readAccess, /valid_read_token/);
  assert.match(concurrency, /high_concurrency/);
});
