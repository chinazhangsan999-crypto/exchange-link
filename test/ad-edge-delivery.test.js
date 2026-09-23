'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

const root = path.join(__dirname, '..');

test('代码广告只下发短期 Edge 地址且前端执行前校验 SHA-256', async () => {
  const [controller, client] = await Promise.all([
    fs.readFile(path.join(root, 'src', 'controllers', 'PublicController.js'), 'utf8'),
    fs.readFile(path.join(root, 'public', 'showcase.js'), 'utf8')
  ]);
  assert.match(controller, /loader_url: `\$\{edgeOrigin\}\/direct\/\$\{ticket\.token\}`/);
  assert.match(controller, /frame_url: `\$\{edgeOrigin\}\/frame\/\$\{ticket\.token\}`/);
  assert.match(controller, /row\.managed_by === 'central'/);
  assert.match(controller, /row\.edge_sync_status === 'synced'/);
  assert.match(controller, /ad_source: row\.managed_by === 'central' \? 'central' : 'local'/);
  assert.doesNotMatch(controller, /ad_code:\s*row\.ad_code/);
  assert.match(client, /verifyCodeIntegrity\(payload\.code, payload\.integrity\)/);
  assert.match(client, /iframe\.setAttribute\('sandbox'/);
  assert.match(client, /webring-runtime-config/);
  assert.doesNotMatch(controller, /\.slice\(0, 1\)/);
  assert.match(client, /for \(const item of normalizeCode\(source\)\)/);
  assert.match(client, /data-showcase-sandbox-slot/);
  assert.match(client, /--showcase-top-offset/);
  assert.doesNotMatch(client, /allow-same-origin/);
});

test('广告 Edge Worker 验证站点票据并区分 Direct 与 Sandbox', async () => {
  const source = await fs.readFile(path.join(root, 'ops', 'ad-edge', 'worker.js'), 'utf8');
  assert.match(source, /site:\$\{payload\.site_id\}/);
  assert.equal(source.includes("const match = /^\\/(direct|frame)\\/"), true);
  assert.match(source, /request\.headers\.get\('origin'\) !== payload\.frontend_origin/);
  assert.match(source, /frame-ancestors \$\{payload\.frontend_origin\}/);
  assert.match(source, /x-ad-edge-source/);
});

test('公共前台源码公开广告 API 域名但不公开票据密钥', async () => {
  const source = await fs.readFile(path.join(root, 'ops', 'public-edge', 'worker.js'), 'utf8');
  assert.match(source, /id="webring-runtime-config"/);
  assert.match(source, /ad_api_origin/);
  assert.doesNotMatch(source, /ad_edge_ticket_key/);
});

test('公共前台 Worker 使用固定兼容日期，不随服务器日期漂移', async () => {
  const source = await fs.readFile(path.join(root, 'src', 'services', 'CloudflarePublicFrontendService.js'), 'utf8');
  assert.match(source, /PUBLIC_WORKER_COMPATIBILITY_DATE = '2024-12-01'/);
  assert.match(source, /compatibility_date: PUBLIC_WORKER_COMPATIBILITY_DATE/);
  assert.match(source, /'\/site-detail', '\/site-detail\.html'/);
});

test('服务器支持在现有进程环境内执行一次性公共前台重部署', async () => {
  const source = await fs.readFile(path.join(root, 'server.js'), 'utf8');
  assert.match(source, /REDEPLOY_PUBLIC_FRONTENDS_ON_START === '1'/);
  assert.match(source, /PUBLIC_FRONTEND_REDEPLOY_RESULT/);
});

test('导航站全部本地广告可批量回传并区分中央与本站来源', async () => {
  const [service, controller, ui] = await Promise.all([
    fs.readFile(path.join(root, 'src', 'services', 'ControlCenterAgentService.js'), 'utf8'),
    fs.readFile(path.join(root, 'src', 'controllers', 'AdminController.js'), 'utf8'),
    fs.readFile(path.join(root, 'public', 'admin', 'ads.js'), 'utf8')
  ]);
  assert.match(service, /async function syncAllLocalAds\(\)/);
  assert.match(service, /const syncAllLocalCodeAds = syncAllLocalAds/);
  assert.match(service, /await AdModel\.listLocalAds\(\)/);
  assert.match(service, /ad_position: String\(row\.ad_position/);
  assert.match(service, /sandbox_options:/);
  assert.match(controller, /await AdModel\.listAds\(\)/);
  assert.match(ui, /总后台下发/);
  assert.match(ui, /同步本站广告/);
  assert.match(ui, /普通图文由本站直接输出/);
});
