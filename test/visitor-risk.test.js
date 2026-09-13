'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const VisitorRiskService = require('../src/services/VisitorRiskService');

test('蜜罐只形成短期访客风险且限制到期后自动解除', () => {
  const visitorId = `risk-test-${Date.now()}`;
  const startedAt = 1_800_000_000_000;
  const first = VisitorRiskService.recordTrapdoor(visitorId, { userAgent: 'Browser' }, startedAt);
  assert.equal(first.score, 30);
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, startedAt), null);

  const repeated = VisitorRiskService.recordTrapdoor(visitorId, { userAgent: 'Browser' }, startedAt + 1000);
  assert.equal(repeated.score, 80);
  assert.equal(repeated.repeatedQuickly, true);
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, startedAt + 1000).retryAfter, 30);
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, startedAt + 31001), null);
  assert.equal(VisitorRiskService.getReadRestriction('another-visitor', startedAt + 1000), null);
});

test('缺少 Fetch Metadata 只是弱信号，不会单独限制正常访客', () => {
  const visitorId = `metadata-test-${Date.now()}`;
  const now = 1_800_000_100_000;
  const first = VisitorRiskService.recordBootstrapSignals(visitorId, {}, now);
  const repeated = VisitorRiskService.recordBootstrapSignals(visitorId, {}, now + 1000);
  assert.equal(first.score, 15);
  assert.equal(repeated.score, 15);
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, now + 1000), null);
});

test('20 秒内遍历八个不同详情 ID 会短暂限制当前访客', () => {
  const visitorId = `detail-scan-${Date.now()}`;
  const now = 1_800_000_200_000;
  for (let id = 1; id <= 7; id += 1) {
    VisitorRiskService.recordDetailRead(visitorId, id, now + id * 100);
  }
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, now + 800), null);
  VisitorRiskService.recordDetailRead(visitorId, 8, now + 800);
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, now + 800).retryAfter, 30);
  assert.equal(VisitorRiskService.getReadRestriction('same-nat-other-visitor', now + 800), null);
});
