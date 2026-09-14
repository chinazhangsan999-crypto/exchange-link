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
  const ids = [1, 3, 5, 7, 9, 11, 13];
  ids.forEach((id, index) => VisitorRiskService.recordDetailRead(visitorId, id, now + (index + 1) * 100));
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, now + 800), null);
  VisitorRiskService.recordDetailRead(visitorId, 15, now + 800);
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, now + 800).retryAfter, 30);
  assert.equal(VisitorRiskService.getReadRestriction('same-nat-other-visitor', now + 800), null);
});

test('连续编号遍历六个详情会提前限制当前访客', () => {
  const visitorId = `sequence-test-${Date.now()}`;
  const now = 1_800_000_300_000;
  for (let id = 20; id <= 24; id += 1) {
    VisitorRiskService.recordDetailRead(visitorId, id, now + id);
  }
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, now + 100), null);
  VisitorRiskService.recordDetailRead(visitorId, 25, now + 101);
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, now + 101).retryAfter, 30);
});

test('脚本客户端特征与缺失 Fetch Metadata 组合计入风险但不连坐其他访客', () => {
  const visitorId = `script-signal-${Date.now()}`;
  const now = 1_800_000_400_000;
  const record = VisitorRiskService.recordBootstrapSignals(visitorId, {
    userAgent: 'python-requests/2.32.0'
  }, now);
  assert.equal(record.score, 65);
  assert.equal(VisitorRiskService.getReadRestriction(visitorId, now), null);
  assert.equal(VisitorRiskService.getReadRestriction('same-nat-normal-browser', now), null);
});
