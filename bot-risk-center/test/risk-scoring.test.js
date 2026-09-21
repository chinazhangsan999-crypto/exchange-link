'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const RiskScoringService = require('../src/services/RiskScoringService');
const DecisionService = require('../src/services/DecisionService');

test('明确 AI 和搜索机器人直接拒绝', () => {
  assert.equal(RiskScoringService.evaluate([{ signal: 'known_ai_crawler' }]).decision, 'deny');
  assert.equal(RiskScoringService.evaluate([{ signal: 'verified_search_bot' }]).decision, 'deny');
});

test('BotD 单一信号只观察，不直接拒绝', () => {
  const result = RiskScoringService.evaluate([{ signal: 'botd_detected' }]);
  assert.equal(result.score, 35);
  assert.equal(result.decision, 'observe');
});

test('组合强证据进入加强挑战', () => {
  const result = RiskScoringService.evaluate([
    { signal: 'botd_detected' },
    { signal: 'high_concurrency' }
  ]);
  assert.equal(result.score, 80);
  assert.equal(result.decision, 'strong_challenge');
});

test('事件幂等且增量游标单调', () => {
  DecisionService.resetForTests();
  const event = {
    eventId: 'event_12345678',
    visitorHash: 'a'.repeat(64),
    eventType: 'sequential_detail_scan',
    occurredAt: Date.now()
  };
  const first = DecisionService.applyEvents('site-a', [event]);
  const duplicate = DecisionService.applyEvents('site-a', [event]);
  assert.equal(first.accepted, 1);
  assert.equal(duplicate.accepted, 0);
  const delta = DecisionService.listDelta('site-a', 0);
  assert.equal(delta.items.length, 1);
  assert.equal(delta.items[0].decision, 'strong_challenge');
});
