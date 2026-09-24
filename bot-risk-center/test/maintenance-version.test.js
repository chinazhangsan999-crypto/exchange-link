'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  compareSemver,
  evaluateMaintenanceVersion,
  sourceForProject
} = require('../src/services/MaintenanceVersionService');

test('maintenance comparison only treats a newer semantic version as an update', () => {
  assert.equal(compareSemver('8.23.0', '7.14.0'), 1);
  assert.equal(compareSemver('3.1137.0', '3.1139.0'), -1);
  assert.equal(compareSemver('17-alpine', 'v17.0.0'), null);

  assert.equal(evaluateMaintenanceVersion({ projectKey: 'node-postgres', installedVersion: '8.23.0' }, { version: '7.14.0', source: 'npm' }), 'version_ahead');
  assert.equal(evaluateMaintenanceVersion({ projectKey: 'aws-route53-sdk', installedVersion: '3.1137.0' }, { version: '3.1139.0', source: 'npm' }), 'update_available');
});

test('maintenance statuses exclude references and unavailable runtime inventories from update alerts', () => {
  assert.equal(evaluateMaintenanceVersion({ projectKey: 'anubis', integrationMode: 'reference' }, { version: '1.27.0', source: 'reference' }), 'reference');
  assert.equal(evaluateMaintenanceVersion({ projectKey: 'cloudflare-workerd', installedVersion: 'cloudflare-managed' }, { source: 'runtime_inventory' }), 'managed');
  assert.equal(evaluateMaintenanceVersion({ projectKey: 'caddy', installedVersion: '' }, { source: 'runtime_inventory' }), 'untracked');
  assert.equal(evaluateMaintenanceVersion({ projectKey: 'postgresql', installedVersion: '17-alpine' }, { source: 'runtime_inventory' }), 'unverifiable');
});

test('known Node packages use the npm registry rather than unrelated GitHub tags', () => {
  assert.deepEqual(sourceForProject({ projectKey: 'node-postgres', integrationMode: 'direct' }), { kind: 'npm', packageName: 'pg' });
  assert.deepEqual(sourceForProject({ projectKey: 'csv-parse', integrationMode: 'direct' }), { kind: 'npm', packageName: 'csv-parse' });
  assert.deepEqual(sourceForProject({ projectKey: 'crowdsec', integrationMode: 'direct' }), { kind: 'runtime_inventory' });
});
