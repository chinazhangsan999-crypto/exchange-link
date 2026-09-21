'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Hmac = require('../src/security/hmac');

test('HMAC 校验成功且 nonce 不可重放', () => {
  Hmac.clearReplayState();
  const secret = 's'.repeat(32);
  const request = {
    clientId: 'nav-main',
    secret,
    method: 'POST',
    pathAndQuery: '/v1/events/batch',
    timestamp: 1_800_000_000_000,
    nonce: 'nonce-123456789',
    body: Buffer.from('{"events":[]}'),
    now: 1_800_000_000_100
  };
  request.signature = Hmac.sign(secret, request);
  assert.equal(Hmac.authenticate(request).ok, true);
  assert.equal(Hmac.authenticate(request).reason, 'nonce_replay');
});

test('过期时间戳和错误签名被拒绝', () => {
  Hmac.clearReplayState();
  const base = {
    clientId: 'nav-main', secret: 's'.repeat(32), method: 'GET',
    pathAndQuery: '/v1/decisions/delta', timestamp: 1000, nonce: 'nonce-old',
    signature: '0'.repeat(64), body: Buffer.alloc(0), now: 100_000
  };
  assert.equal(Hmac.authenticate(base).reason, 'timestamp_out_of_range');
});
