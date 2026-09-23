'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '..');

test('识别质量与链路健康合并到导航站接入，名单合并到人工规则', () => {
  const html = fs.readFileSync(path.join(root, 'public', 'admin.html'), 'utf8');
  const script = fs.readFileSync(path.join(root, 'public', 'admin.js'), 'utf8');
  const routes = fs.readFileSync(path.join(root, 'src', 'routes', 'index.js'), 'utf8');
  for (const tab of ['connections', 'suspects', 'detection', 'rules', 'alerts', 'maintenance', 'security', 'audits']) {
    assert.match(html, new RegExp(`data-tab="${tab}"`));
  }
  assert.doesNotMatch(html, /data-tab="quality"/);
  assert.match(html, /panel-connections[\s\S]+quality-pass-rate[\s\S]+pipeline-body/);
  assert.match(html, /panel-rules[\s\S]+identity-rules-section/);
  assert.doesNotMatch(html.match(/id="panel-detection"[^\n]*/)?.[0] || '', /identity-form/);
  assert.match(html, /detection-body/);
  assert.match(html, /quality-pass-rate/);
  assert.match(html, /policies-body/);
  assert.match(html, /security-sessions-body/);
  assert.match(html, /github-token-form/);
  assert.match(html, /GitHub API Token/);
  assert.match(html, /revoke-all-sessions/);
  assert.match(script, /loadDetection/);
  assert.match(script, /loadQuality/);
  assert.match(script, /loadIdentityLists/);
  assert.match(script, /loadSecurity/);
  assert.match(routes, /detection\/capabilities/);
  assert.match(routes, /security\/credentials/);
  assert.match(routes, /security\/github-token/);
  assert.match(routes, /sessions\/revoke-others/);
  assert.match(routes, /sessions\/revoke-all/);
});

test('GitHub API Token 只以加密凭据保存且维护检查按后台凭据优先', () => {
  const migration = fs.readFileSync(path.join(root, 'migrations', '011_github_api_settings.sql'), 'utf8');
  const storage = fs.readFileSync(path.join(root, 'src', 'services', 'StorageService.js'), 'utf8');
  const maintenance = fs.readFileSync(path.join(root, 'src', 'services', 'MaintenanceService.js'), 'utf8');
  assert.match(migration, /github_api_settings/);
  assert.match(migration, /token_ciphertext/);
  assert.match(storage, /CredentialService\.encrypt\(token\)/);
  assert.match(storage, /save_github_api_token/);
  assert.match(maintenance, /getGitHubApiSettings\(\{ includeToken: true \}\)/);
  assert.match(maintenance, /githubSettings\.token \|\| GITHUB_API_TOKEN/);
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
  const projectRoot = path.resolve(process.env.WEBRING_PROJECT_ROOT || path.join(root, '..'));
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

test('人工名单支持筛选分页、编辑启停、命中统计和冲突保护', () => {
  const script = fs.readFileSync(path.join(root, 'public', 'admin.js'), 'utf8');
  const routes = fs.readFileSync(path.join(root, 'src', 'routes', 'index.js'), 'utf8');
  const storage = fs.readFileSync(path.join(root, 'src', 'services', 'StorageService.js'), 'utf8');
  const migration = fs.readFileSync(path.join(root, 'migrations', '009_identity_controls.sql'), 'utf8');
  for (const marker of ['identity-filter-list', 'identity-filter-site', 'identity-filter-keyword', 'identity-prev', 'edit-identity', 'toggle-identity']) assert.match(script, new RegExp(marker));
  assert.match(routes, /identity-lists\/:listType\/:id\/toggle/);
  assert.match(routes, /router\.put\('\/admin\/api\/detection\/identity-lists/);
  assert.match(storage, /IDENTITY_CONFLICT/);
  assert.match(storage, /hit_count=hit_count\+1/);
  assert.match(migration, /ADD COLUMN IF NOT EXISTS enabled/);
  assert.match(migration, /omrilotan\/isbot/);
  assert.match(migration, /redis\/node-redis/);
});
