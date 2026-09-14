'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('后台数据模块以 HttpOnly Cookie 会话状态启动加载', () => {
  const directory = path.join(__dirname, '..', 'public', 'admin');
  for (const file of ['app.js', 'traffic-logs.js', 'review.js', 'ads.js', 'monitor.js']) {
    const source = fs.readFileSync(path.join(directory, file), 'utf8');
    assert.doesNotMatch(source, /const token\s*=\s*\(\)\s*=>\s*''/);
    assert.match(source, /window\.adminSessionActive\s*===\s*true\s*\?\s*'cookie-session'/);
  }

  const initializer = fs.readFileSync(path.join(directory, 'init.js'), 'utf8');
  assert.match(initializer, /Bearer\\s\*\(\?:cookie-session\)\?/);
});
