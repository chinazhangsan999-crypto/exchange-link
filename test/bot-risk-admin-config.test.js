'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('风险中心后台配置严格区分内网与 HTTPS 外网线路', () => {
  const BotRiskClient = require('../src/services/BotRiskClient');
  const base = {
    enabled: true,
    clientId: 'nav-main',
    siteKey: 'webring-main',
    secret: '0123456789abcdef0123456789abcdef',
    mode: 'observe'
  };
  assert.equal(BotRiskClient.normalizeConfig({ ...base, connectionType: 'internal', baseUrl: 'http://10.0.0.8:4100' }).baseUrl, 'http://10.0.0.8:4100');
  assert.equal(BotRiskClient.normalizeConfig({ ...base, connectionType: 'https', baseUrl: 'https://risk.example.com' }).connectionType, 'https');
  assert.throws(() => BotRiskClient.normalizeConfig({ ...base, connectionType: 'https', baseUrl: 'http://risk.example.com' }), /HTTPS/);
  assert.throws(() => BotRiskClient.normalizeConfig({ ...base, connectionType: 'internal', baseUrl: 'http://8.8.8.8:4100' }), /私网/);
});
