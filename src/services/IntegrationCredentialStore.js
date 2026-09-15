'use strict';

const fs = require('fs');
const path = require('path');
const {
  IS_PRODUCTION,
  CONTROL_CENTER_CREDENTIAL_FILE,
  CONTROL_CENTER_URL,
  CONTROL_CENTER_SITE_CREDENTIAL,
  IP_INTELLIGENCE_CREDENTIAL_FILE,
  IP_INTELLIGENCE_BASE_URL,
  IP_INTELLIGENCE_CLIENT_ID,
  IP_INTELLIGENCE_CLIENT_SECRET,
  IP_INTELLIGENCE_ENABLED
} = require('../config/env');

function resolveCredentialPath(configuredPath, fallbackName) {
  if (configuredPath) return path.resolve(configuredPath);
  if (IS_PRODUCTION) return `/home/niaiwo/app-secrets/${fallbackName}`;
  return path.join(__dirname, '..', '..', 'data', 'secrets', fallbackName);
}

const paths = {
  controlCenter: resolveCredentialPath(CONTROL_CENTER_CREDENTIAL_FILE, 'control-center-site.json'),
  ipIntelligence: resolveCredentialPath(IP_INTELLIGENCE_CREDENTIAL_FILE, 'ip-intelligence.json')
};

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw new Error(`无法读取接入凭据文件：${error.message}`);
  }
}

async function writeJsonAtomic(file, value) {
  await fs.promises.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.promises.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await fs.promises.chmod(temporary, 0o600);
  await fs.promises.rename(temporary, file);
}

function controlCenterConfig() {
  const stored = readJson(paths.controlCenter) || {};
  return {
    url: String(stored.url || CONTROL_CENTER_URL || '').trim().replace(/\/$/, ''),
    credential: String(stored.credential || CONTROL_CENTER_SITE_CREDENTIAL || '').trim()
  };
}

function ipIntelligenceConfig() {
  const stored = readJson(paths.ipIntelligence) || {};
  return {
    enabled: stored.enabled === undefined ? IP_INTELLIGENCE_ENABLED : stored.enabled !== false,
    baseUrl: String(stored.base_url || stored.baseUrl || IP_INTELLIGENCE_BASE_URL || '').trim().replace(/\/$/, ''),
    clientId: String(stored.client_id || stored.clientId || IP_INTELLIGENCE_CLIENT_ID || '').trim(),
    secret: String(stored.secret || IP_INTELLIGENCE_CLIENT_SECRET || '').trim()
  };
}

async function saveControlCenter(config) {
  await writeJsonAtomic(paths.controlCenter, { url: config.url, credential: config.credential });
}

async function saveIpIntelligence(config) {
  await writeJsonAtomic(paths.ipIntelligence, {
    enabled: config.enabled !== false,
    base_url: config.baseUrl,
    client_id: config.clientId,
    secret: config.secret
  });
}

module.exports = {
  paths,
  controlCenterConfig,
  ipIntelligenceConfig,
  saveControlCenter,
  saveIpIntelligence
};
