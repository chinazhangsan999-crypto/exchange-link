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

  const html = fs.readFileSync(path.join(directory, 'index.html'), 'utf8');
  assert.doesNotMatch(html, /webring_admin_token|webring_login_source/);
  assert.match(html, /credentials:opt\.credentials\|\|'same-origin'/);
});
