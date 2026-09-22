'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { IS_PRODUCTION } = require('../config/env');

const credentialPath = process.env.RECOVERY_CREDENTIAL_FILE
  ? path.resolve(process.env.RECOVERY_CREDENTIAL_FILE)
  : (IS_PRODUCTION
    ? path.join(os.homedir(), 'app-secrets', 'recovery-system.json')
    : path.join(__dirname, '..', '..', 'data', 'secrets', 'recovery-system.json'));

function read() {
  try { return JSON.parse(fs.readFileSync(credentialPath, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return {};
    throw new Error(`无法读取恢复系统凭据：${error.message}`);
  }
}

async function write(value) {
  await fs.promises.mkdir(path.dirname(credentialPath), { recursive: true, mode: 0o700 });
  const temporary = `${credentialPath}.${process.pid}.${Date.now()}.tmp`;
  await fs.promises.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await fs.promises.chmod(temporary, 0o600);
  await fs.promises.rename(temporary, credentialPath);
}

function signingKeys(profileId = 1) {
  const root = read();
  const stored = root.signing_profiles?.[String(profileId)] || (Number(profileId) === 1 ? root.signing : null) || {};
  return {
    current: stored.current || null,
    next: stored.next || null
  };
}

async function saveSigningKeys(keys, profileId = 1) {
  const stored = read();
  const profiles = { ...(stored.signing_profiles || {}) };
  profiles[String(profileId)] = { current: keys.current || null, next: keys.next || null };
  const next = { ...stored, signing_profiles: profiles };
  if (Number(profileId) === 1 && stored.signing) delete next.signing;
  await write(next);
}

function cloudflareConfig() {
  const stored = read().cloudflare || {};
  return {
    reuseCentral: stored.reuse_central !== false,
    accountId: String(stored.account_id || '').trim(),
    apiToken: String(stored.api_token || '').trim()
  };
}

async function saveCloudflareConfig(config) {
  const stored = read();
  const previous = stored.cloudflare || {};
  await write({
    ...stored,
    cloudflare: {
      reuse_central: config.reuseCentral !== false,
      account_id: String(config.accountId || previous.account_id || '').trim(),
      api_token: String(config.apiToken || previous.api_token || '').trim()
    }
  });
}

function dnsChannel(credentialKey) {
  const stored = read().dns_channels?.[String(credentialKey)] || {};
  return {
    providerId: String(stored.provider_id || '').trim().toLowerCase(),
    credentials: stored.credentials && typeof stored.credentials === 'object' ? { ...stored.credentials } : {}
  };
}

async function saveDnsChannel(credentialKey, providerId, credentials) {
  const stored = read();
  const channels = { ...(stored.dns_channels || {}) };
  channels[String(credentialKey)] = {
    provider_id: String(providerId || '').trim().toLowerCase(),
    credentials: { ...(credentials || {}) }
  };
  await write({ ...stored, dns_channels: channels });
}

async function deleteDnsChannel(credentialKey) {
  const stored = read();
  const channels = { ...(stored.dns_channels || {}) };
  delete channels[String(credentialKey)];
  await write({ ...stored, dns_channels: channels });
}

module.exports = {
  credentialPath,
  signingKeys,
  saveSigningKeys,
  cloudflareConfig,
  saveCloudflareConfig,
  dnsChannel,
  saveDnsChannel,
  deleteDnsChannel
};
