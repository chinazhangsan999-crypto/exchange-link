'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const InflowAttributionService = require('../src/services/InflowAttributionService');

test('入站归属在 Cookie 无法解析时可按稳定匿名访客回退', () => {
  const visitorId = `test-visitor-${Date.now()}`;
  const attribution = { visitId: 'visit-123', sourcePartnerId: 42 };

  assert.equal(InflowAttributionService.remember(visitorId, attribution), true);
  assert.deepEqual(InflowAttributionService.recall(visitorId), attribution);
  InflowAttributionService.forget(visitorId);
  assert.equal(InflowAttributionService.recall(visitorId), null);
});

test('无效归属不会进入回退缓存', () => {
  assert.equal(InflowAttributionService.remember('invalid-visitor', { visitId: '', sourcePartnerId: 42 }), false);
  assert.equal(InflowAttributionService.remember('invalid-visitor', { visitId: 'visit', sourcePartnerId: 0 }), false);
});
