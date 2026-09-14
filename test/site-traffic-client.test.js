'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '..');
const publicController = fs.readFileSync(path.join(root, 'src', 'controllers', 'PublicController.js'), 'utf8');
const publicRoutes = fs.readFileSync(path.join(root, 'src', 'routes', 'public.js'), 'utf8');
const common = fs.readFileSync(path.join(root, 'public', 'common.js'), 'utf8');

test('全站 PV 使用页面主动上报，而不是静态响应 finish 事件', () => {
  assert.match(publicController, /function recordSitePageView\(req, res\)/);
  assert.match(publicController, /SiteTrafficService\.recordPageView\(\{ visitorId, normalizedIp, occurredAt: new Date\(\) \}\)/);
  assert.doesNotMatch(publicController, /res\.once\('finish'/);
  assert.match(publicRoutes, /router\.post\('\/api\/track\/site-page-view'/);
  assert.match(common, /fetch\('\/api\/track\/site-page-view'/);
});

test('全站与入站后 PV 同时兼容详情页净化路径和 html 路径', () => {
  const supportedPaths = ['/', '/index.html', '/site-detail', '/site-detail.html'];
  const browserPattern = /^\/(?:index\.html|site-detail(?:\.html)?)?$/;
  const serverPattern = /^\/(?:index\.html|site-detail(?:\.html)?|publish\.html)?$/;

  for (const pagePath of supportedPaths) {
    assert.equal(browserPattern.test(pagePath), true, `浏览器应上报 ${pagePath}`);
    assert.equal(serverPattern.test(pagePath), true, `服务端应接收 ${pagePath}`);
  }
  assert.match(common, /site-detail\(\?:\\\.html\)\?/);
  assert.match(publicController, /site-detail\(\?:\\\.html\)\?/);
});
