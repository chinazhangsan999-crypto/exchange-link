'use strict';

const crypto = require('crypto');
const { CREDENTIAL_KEY } = require('../config/env');

const key = crypto.createHash('sha256').update(CREDENTIAL_KEY).digest();

function generateSecret() {
  return crypto.randomBytes(32).toString('base64url');
}

function encrypt(secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(secret), 'utf8'), cipher.final()]);
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64')
  };
}

function decrypt(record) {
  if (!record?.secret_ciphertext || !record?.secret_iv || !record?.secret_tag) return null;
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(record.secret_iv, 'base64'));
  decipher.setAuthTag(Buffer.from(record.secret_tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(record.secret_ciphertext, 'base64')),
    decipher.final()
  ]).toString('utf8');
}

module.exports = { generateSecret, encrypt, decrypt };
