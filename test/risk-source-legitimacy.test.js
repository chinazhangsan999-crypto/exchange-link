'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { calculateSourceLegitimacy } = require('../src/services/RiskService');

test('有效 SID 的空 Referer 保留审计值但不计入来源异常', () => {
  const result = calculateSourceLegitimacy({
    empty_referer_count: 0,
    raw_empty_referer_count: 1,
    sid_no_referer_count: 1
  }, 1);

  assert.deepEqual(result, {
    emptyRefererCount: 0,
    emptyRefererRatio: 0,
    rawEmptyRefererCount: 1,
    rawEmptyRefererRatio: 1,
    sidNoRefererCount: 1
  });
});

test('无 Referer 且无有效 SID 的记录仍计入来源异常比例', () => {
  const result = calculateSourceLegitimacy({
    empty_referer_count: 2,
    raw_empty_referer_count: 3,
    sid_no_referer_count: 1
  }, 4);

  assert.equal(result.emptyRefererCount, 2);
  assert.equal(result.emptyRefererRatio, 0.5);
  assert.equal(result.rawEmptyRefererRatio, 0.75);
});
