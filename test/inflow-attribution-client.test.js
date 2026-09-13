'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');

test('入站确认使用可接收 Cookie 的 fetch，并在详情页跳转前短暂等待', async () => {
  const source = await fs.readFile(path.join(__dirname, '..', 'public', 'script.js'), 'utf8');

  assert.match(source, /fetch\('\/api\/track\/ping'/);
  assert.match(source, /credentials:'same-origin'/);
  assert.match(source, /keepalive:true/);
  assert.match(source, /fetch\('\/api\/track\/page-view'/);
  assert.match(source, /入口页在有效心跳确认后立即记为第一条站内浏览/);
  assert.doesNotMatch(source, /navigator\.sendBeacon/);
  assert.match(source, /destination\.pathname==='\/site-detail\.html'/);
  assert.match(source, /waitFor\(1200\)/);
});
