'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('后台数据模块以 HttpOnly Cookie 会话状态启动加载', () => {
  const directory = path.join(__dirname, '..', 'public', 'admin');
  for (const file of ['app.js', 'traffic-logs.js', 'review.js', 'ads.js', 'monitor.js']) {
    const source = fs.readFileSync(path.join(directory, file), 'utf8');
    assert.doesNotMatch(source, /Authorization\s*:/);
    assert.match(source, /credentials:\s*'same-origin'/);
  }

  const initializer = fs.readFileSync(path.join(directory, 'init.js'), 'utf8');
  assert.doesNotMatch(initializer, /cookie-session/);
  assert.match(initializer, /session\/exchange/);
  assert.match(initializer, /validTabs[^\n]+['"]cloudflare['"]/);
  assert.match(initializer, /#cloudflare-tab'[\s\S]+#settings-tab'/);
  assert.match(initializer, /tab === 'cloudflare'[\s\S]+loadCloudflareSettings/);

  const html = fs.readFileSync(path.join(directory, 'index.html'), 'utf8');
  assert.doesNotMatch(html, /webring_admin_token|webring_login_source/);
  assert.match(html, /credentials:opt\.credentials\|\|'same-origin'/);

  const integrations = fs.readFileSync(path.join(directory, 'password.js'), 'utf8');
  assert.match(integrations, /const form = event\.currentTarget;/);
  assert.match(integrations, /ip-intelligence-integration[\s\S]+bot-risk-center-integration/);
  assert.match(integrations, /integrations\/bot-risk-center\/test/);
  assert.match(integrations, /Client Secret[\s\S]+不会回显/);
  assert.doesNotMatch(integrations, /await[^;]+;\s*event\.currentTarget\.elements/s);

  const review = fs.readFileSync(path.join(directory, 'review.js'), 'utf8');
  assert.match(review, /cloudflare\.append\(apiEdge, inventory, frontendOrigins\)/);
  assert.match(review, /cloudflare-central-summary/);
  assert.match(review, /cloudflare-account-body/);
  assert.match(review, /cloudflare-worker-body/);
  assert.match(review, /cloudflare-central-access-form/);
  assert.match(review, /cloudflare-bootstrap\/adopt/);
  assert.doesNotMatch(review, /id="api-edge-sync-form"/);
  assert.doesNotMatch(review, /id="cloudflare-bootstrap-form"/);
  assert.match(review, /settings\.append\(analytics, matrix\)/);
  assert.match(review, /window\.loadCloudflareSettings = loadCloudflareSettings/);
  assert.doesNotMatch(review, /loadAllSettings\(\)[^{]+\{[^}]+loadFrontendOrigins/s);
});
