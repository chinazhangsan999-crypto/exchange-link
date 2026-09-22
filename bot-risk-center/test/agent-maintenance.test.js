'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const riskRoot = path.join(__dirname, '..');
const projectRoot = path.resolve(process.env.WEBRING_PROJECT_ROOT || path.join(riskRoot, '..'));

test('导航站维护接口沿用 HMAC 并实施细粒度 scope', () => {
  const routes = fs.readFileSync(path.join(riskRoot, 'src/routes/index.js'), 'utf8');
  const auth = fs.readFileSync(path.join(riskRoot, 'src/middlewares/clientAuth.js'), 'utf8');
  assert.match(routes, /\/v1\/agent\/inventory.*maintenance\.inventory\.write/);
  assert.match(routes, /\/v1\/agent\/advisories.*maintenance\.advisory\.read/);
  assert.match(routes, /\/v1\/agent\/test-results.*maintenance\.test-result\.write/);
  assert.match(auth, /requireClientScope[\s\S]+Client scope denied/);
});

test('缺少维护 scope 的已认证客户端仍被拒绝', () => {
  const { requireClientScope } = require(path.join(riskRoot, 'src/middlewares/clientAuth'));
  let statusCode = 0;
  let nextCalled = false;
  const response = {
    status(code) { statusCode = code; return this; },
    json(payload) { return payload; }
  };
  requireClientScope('maintenance.inventory.write')(
    { riskClient: { scopes: ['risk.events.write'] } }, response, () => { nextCalled = true; }
  );
  assert.equal(statusCode, 403);
  assert.equal(nextCalled, false);
});

test('运行清单迁移和只读维护快照包含站点版本矩阵', () => {
  const migration = fs.readFileSync(path.join(riskRoot, 'migrations/004_agent_maintenance.sql'), 'utf8');
  const storage = fs.readFileSync(path.join(riskRoot, 'src/services/StorageService.js'), 'utf8');
  const html = fs.readFileSync(path.join(riskRoot, 'public/admin.html'), 'utf8');
  assert.match(migration, /site_runtime_inventory/);
  assert.match(migration, /maintenance_advisories/);
  assert.match(migration, /maintenance_test_results/);
  assert.match(storage, /getMaintenanceSnapshot[\s\S]+listSiteMaintenanceMatrix/);
  assert.match(html, /站点运行版本矩阵/);
});

test('导航站清单只包含允许的版本证明字段', () => {
  const client = require(path.join(projectRoot, 'src/services/BotRiskClient'));
  const inventory = client.buildRuntimeInventory();
  assert.equal(inventory.schemaVersion, 'inventory-v1');
  assert.match(inventory.nodeVersion, /^v\d+/);
  assert.ok(inventory.components.some(item => item.key === 'botd' && /^[a-f0-9]{64}$/.test(item.assetSha256)));
  assert.equal(Object.hasOwn(inventory, 'environment'), false);
  assert.equal(Object.hasOwn(inventory, 'secret'), false);
  assert.equal(Object.hasOwn(inventory, 'database'), false);
});
