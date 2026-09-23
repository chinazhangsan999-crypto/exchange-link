'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('维护接口只暴露脱敏读取路由并由短期令牌保护', () => {
  const root = path.join(__dirname, '..');
  const routes = fs.readFileSync(path.join(root, 'src', 'routes', 'index.js'), 'utf8');
  const auth = fs.readFileSync(path.join(root, 'src', 'middlewares', 'maintenanceAuth.js'), 'utf8');
  const controller = fs.readFileSync(path.join(root, 'src', 'controllers', 'MaintenanceController.js'), 'utf8');
  assert.match(routes, /\/v1\/maintenance\/snapshot.*requireMaintenanceRead/);
  assert.match(routes, /\/v1\/maintenance\/upstreams.*requireMaintenanceRead/);
  assert.match(auth, /Authorization[\s\S]+Bearer[\s\S]+consumeMaintenanceToken/);
  assert.doesNotMatch(controller, /password|secret|ciphertext|environment/i);
});

test('组件管理迁移、后台按钮和更新告警配置完整', () => {
  const root = path.join(__dirname, '..');
  const migration = fs.readFileSync(path.join(root, 'migrations', '003_maintenance.sql'), 'utf8');
  const html = fs.readFileSync(path.join(root, 'public', 'admin.html'), 'utf8');
  const script = fs.readFileSync(path.join(root, 'public', 'admin.js'), 'utf8');
  const alert = fs.readFileSync(path.join(root, 'src', 'services', 'AlertService.js'), 'utf8');
  assert.match(migration, /maintenance_projects/);
  assert.match(migration, /maintenance_tokens/);
  assert.match(migration, /upstream_update_alert_enabled/);
  assert.match(html, /data-tab="maintenance"/);
  assert.match(html, /立即检查全部项目/);
  assert.match(html, /生成 15 分钟只读令牌/);
  assert.match(html, /只读诊断接口/);
  assert.match(html, /上游更新信息接口/);
  assert.match(html, /复制接口地址/);
  assert.match(html, /更新时间[\s\S]+跟进状态/);
  assert.match(script, /follow-project[\s\S]+ignore-project[\s\S]+reset-project/);
  assert.match(alert, /notifyUpstreamUpdates/);
  assert.match(alert, /TELEGRAM_TEXT_LIMIT = 3800/);
  assert.match(alert, /BARK_BODY_BYTES = 2400/);
});

test('组件更新表格保留原生单元格布局并使用稳定列宽', () => {
  const root = path.join(__dirname, '..');
  const html = fs.readFileSync(path.join(root, 'public', 'admin.html'), 'utf8');
  const css = fs.readFileSync(path.join(root, 'public', 'admin.css'), 'utf8');
  assert.match(html, /<table class="maintenance-table upstream-table">/);
  assert.match(html, /<table class="maintenance-table matrix-table">/);
  assert.match(css, /\.maintenance-table \{[^}]*table-layout: fixed;/);
  assert.match(css, /td\.version-stack > \* \{ display: block; \}/);
  assert.doesNotMatch(css, /\.version-stack \{[^}]*display:\s*grid/);
});

test('组件清单覆盖风险中心、导航站、边缘基础设施与全部参考项目', () => {
  const root = path.join(__dirname, '..');
  const migration = fs.readFileSync(path.join(root, 'migrations', '010_maintenance_component_inventory.sql'), 'utf8');
  const script = fs.readFileSync(path.join(root, 'public', 'admin.js'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'src', 'services', 'MaintenanceService.js'), 'utf8');
  for (const project of [
    'nodejs', 'express', 'node-postgres', 'pino', 'node-redis', 'postgresql', 'redis-server', 'caddy',
    'cloudflare-workers-sdk', 'cloudflare-workerd', 'botd', 'isbot', 'alicloud-dns-sdk', 'aws-route53-sdk',
    'tencentcloud-dnspod-sdk', 'fingerprintjs', 'anubis', 'coraza', 'mcaptcha', 'openappsec', 'ja4-nginx',
    'caddy-defender', 'creepjs', 'safeline', 'bunkerweb', 'goodbots', 'crawler-user-agents'
  ]) assert.match(migration, new RegExp(`'${project}'`));
  assert.match(migration, /used_by JSONB/);
  assert.match(script, /maintenance-scope-filter/);
  assert.match(script, /item\.usedBy/);
  assert.match(service, /CHECK_BATCH_SIZE = 4/);
  assert.match(service, /Promise\.all\(batch\.map/);
});
