'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  IS_PRODUCTION,
  EDGE_ACCESS_SECRET,
  BROWSER_ACCESS_TTL_MS
} = require('../config/env');

const secretFile = process.env.BROWSER_ACCESS_SECRET_FILE
  ? path.resolve(process.env.BROWSER_ACCESS_SECRET_FILE)
  : (IS_PRODUCTION
    ? path.join(os.homedir(), 'app-secrets', 'browser-access.json')
    : path.join(__dirname, '..', '..', 'data', 'secrets', 'browser-access.json'));

let stored = loadStored();

function cleanSecret(value) {
  const secret = String(value || '').trim();
  return secret.length >= 32 ? secret : '';
}

function loadStored() {
  try {
    const value = JSON.parse(fs.readFileSync(secretFile, 'utf8'));
    return {
      currentSecret: cleanSecret(value.current_secret || value.currentSecret),
      createdAt: String(value.created_at || value.createdAt || ''),
      previousSecret: cleanSecret(value.previous_secret || value.previousSecret),
      previousExpiresAt: String(value.previous_expires_at || value.previousExpiresAt || '')
    };
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw new Error(`无法读取浏览器通行证密钥：${error.message}`);
  }
}

function environmentSecret() {
  return cleanSecret(EDGE_ACCESS_SECRET);
}

function getCurrentSecret() {
  return cleanSecret(stored.currentSecret) || environmentSecret();
}

function fingerprint(secret = getCurrentSecret()) {
  if (!secret) return '';
  const digest = crypto.createHash('sha256').update(secret).digest('hex');
  return `${digest.slice(0, 4)}…${digest.slice(-4)}`;
}

async function writeStored(next) {
  await fs.promises.mkdir(path.dirname(secretFile), { recursive: true, mode: 0o700 });
  const temporary = `${secretFile}.${process.pid}.${Date.now()}.tmp`;
  await fs.promises.writeFile(temporary, `${JSON.stringify({
    version: 1,
    current_secret: next.currentSecret,
    created_at: next.createdAt,
    previous_secret: next.previousSecret || '',
    previous_expires_at: next.previousExpiresAt || null
  }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await fs.promises.chmod(temporary, 0o600);
  await fs.promises.rename(temporary, secretFile);
  stored = next;
}

function generateSecret() {
  return crypto.randomBytes(48).toString('base64url');
}

async function ensureSecret(now = Date.now()) {
  const current = getCurrentSecret();
  if (current) return status(now);
  const createdAt = new Date(now).toISOString();
  await writeStored({ currentSecret: generateSecret(), createdAt });
  return status(now);
}

async function rotateSecret(now = Date.now()) {
  const current = getCurrentSecret();
  const createdAt = new Date(now).toISOString();
  await writeStored({
    currentSecret: generateSecret(),
    createdAt,
    previousSecret: current,
    previousExpiresAt: current ? new Date(now + BROWSER_ACCESS_TTL_MS).toISOString() : ''
  });
  return status(now);
}

function getVerificationSecrets(now = Date.now()) {
  const secrets = [getCurrentSecret()];
  if (stored.previousSecret && Date.parse(stored.previousExpiresAt || '') > now) {
    secrets.push(stored.previousSecret);
  }
  return [...new Set(secrets.filter(Boolean))];
}

function status(now = Date.now()) {
  const current = getCurrentSecret();
  return {
    configured: Boolean(current),
    fingerprint: fingerprint(current),
    createdAt: stored.currentSecret ? stored.createdAt || null : null,
    source: stored.currentSecret ? 'managed' : (environmentSecret() ? 'environment' : 'missing'),
    previousValidUntil: stored.previousSecret && Date.parse(stored.previousExpiresAt || '') > now
      ? stored.previousExpiresAt : null
  };
}

function resetForTests() {
  stored = loadStored();
}

module.exports = {
  ensureSecret,
  rotateSecret,
  getCurrentSecret,
  getVerificationSecrets,
  status,
  resetForTests
};
