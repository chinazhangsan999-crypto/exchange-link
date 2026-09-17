'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..');

test('首页只注册可审计的同源 PWA Service Worker', () => {
  const html = fs.readFileSync(path.join(projectRoot, 'public', 'index.html'), 'utf8');
  assert.match(html, /serviceWorker\.register\('\/sw\.js'\)/);
  assert.doesNotMatch(html, /vitals-monitor\.js|google-analytics-v4\.js|error-tracker\.min\.js/);
  assert.doesNotMatch(html, /__GLOBAL_APP_CONFIG__|fake-router-node|decoy-alpha|decoy-beta/);
});

test('前台不再打包虚假遥测与伪装分析脚本', () => {
  for (const file of ['vitals-monitor.js', 'google-analytics-v4.js', 'error-tracker.min.js']) {
    assert.equal(fs.existsSync(path.join(projectRoot, 'public', file)), false, `${file} 应已移除`);
  }
});
