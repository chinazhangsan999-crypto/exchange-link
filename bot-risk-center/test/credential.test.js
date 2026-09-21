'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const CredentialService = require('../src/services/CredentialService');

test('动态 HMAC 密钥加密后可以还原且明文不落库', () => {
  const secret = CredentialService.generateSecret();
  const encrypted = CredentialService.encrypt(secret);
  assert.ok(secret.length >= 32);
  assert.notEqual(encrypted.ciphertext, secret);
  assert.equal(CredentialService.decrypt({
    secret_ciphertext: encrypted.ciphertext,
    secret_iv: encrypted.iv,
    secret_tag: encrypted.tag
  }), secret);
});
