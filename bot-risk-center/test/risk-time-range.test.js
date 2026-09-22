'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

test('风险中心时间范围由后端统一约束，并同步作用于概览、汇总和疑似访客', () => {
  const root = path.join(__dirname, '..');
  const storage = fs.readFileSync(path.join(root, 'src', 'services', 'StorageService.js'), 'utf8');
  const controller = fs.readFileSync(path.join(root, 'src', 'controllers', 'AdminController.js'), 'utf8');
  const html = fs.readFileSync(path.join(root, 'public', 'admin.html'), 'utf8');
  const script = fs.readFileSync(path.join(root, 'public', 'admin.js'), 'utf8');

  assert.match(storage, /'24h'.*24 hours/);
  assert.match(storage, /'7d'.*7 days/);
  assert.match(storage, /'30d'.*30 days/);
  assert.match(storage, /all:.*全部历史/);
  assert.match(storage, /function resolveRiskWindow/);
  assert.match(storage, /getAdminOverview\(range = '24h'\)/);
  assert.match(storage, /getRiskSummary\(siteKey = '', range = '24h'\)/);
  assert.match(storage, /listSuspects\(\{ siteKey = '', page = 1, limit = 50, minScore = 25, range = '24h'/);
  assert.match(controller, /getAdminOverview\(String\(req\.query\.range \|\| '24h'\)\)/);
  assert.match(controller, /getRiskSummary\(String\(req\.query\.siteKey \|\| ''\), String\(req\.query\.range \|\| '24h'\)\)/);
  assert.match(html, /id="suspect-range-filter"[\s\S]*近 7 天[\s\S]*近 30 天[\s\S]*全部历史/);
  assert.match(script, /range: state\.riskRange/);
  assert.match(script, /Promise\.all\(\[loadOverview\(\), loadSuspects\(\)\]\)/);
});
