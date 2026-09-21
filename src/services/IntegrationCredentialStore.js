'use strict';

const fs = require('fs');
const os = require('os');
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
  IP_INTELLIGENCE_ENABLED,
  BOT_RISK_CREDENTIAL_FILE,
  BOT_RISK_CENTER_URL,
  BOT_RISK_CLIENT_ID,
  BOT_RISK_CLIENT_SECRET,
  BOT_RISK_SITE_KEY,
  BOT_RISK_CENTER_ENABLED,
  BOT_RISK_ALLOW_PRIVATE_HTTP,
  BOT_GATE_MODE
} = require('../config/env');

function resolveCredentialPath(configuredPath, fallbackName) {
  if (configuredPath) return path.resolve(configuredPath);
  if (IS_PRODUCTION) return path.join(os.homedir(), 'app-secrets', fallbackName);
  return path.join(__dirname, '..', '..', 'data', 'secrets', fallbackName);
}

const paths = {
  controlCenter: resolveCredentialPath(CONTROL_CENTER_CREDENTIAL_FILE, 'control-center-site.json'),
  ipIntelligence: resolveCredentialPath(IP_INTELLIGENCE_CREDENTIAL_FILE, 'ip-intelligence.json'),
  botRisk: resolveCredentialPath(BOT_RISK_CREDENTIAL_FILE, 'bot-risk-center.json'),
  // Cloudflare API Token 仅用于把后台维护的前端 Origin 同步到 API Edge Worker。
  // 与其他外部接入凭据一致，生产环境保存在权限 600 的独立文件中，而非 SQLite。
  cloudflareApiEdge: resolveCredentialPath('', 'cloudflare-api-edge.json')
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

function botRiskConfig() {
  const stored = readJson(paths.botRisk) || {};
  return {
    enabled: stored.enabled === undefined ? BOT_RISK_CENTER_ENABLED : stored.enabled === true,
    connectionType: String(stored.connection_type || stored.connectionType
      || (BOT_RISK_ALLOW_PRIVATE_HTTP ? 'internal' : 'https')).trim().toLowerCase(),
    baseUrl: String(stored.base_url || stored.baseUrl || BOT_RISK_CENTER_URL || '').trim().replace(/\/$/, ''),
    clientId: String(stored.client_id || stored.clientId || BOT_RISK_CLIENT_ID || '').trim(),
    secret: String(stored.secret || BOT_RISK_CLIENT_SECRET || '').trim(),
    siteKey: String(stored.site_key || stored.siteKey || BOT_RISK_SITE_KEY || 'webring-main').trim(),
    mode: String(stored.mode || BOT_GATE_MODE || 'off').trim().toLowerCase()
  };
}

function cloudflareApiEdgeConfig() {
  const stored = readJson(paths.cloudflareApiEdge) || {};
  return {
    accountId: String(stored.account_id || stored.accountId || '').trim(),
    workerName: String(stored.worker_name || stored.workerName || '').trim(),
    apiToken: String(stored.api_token || stored.apiToken || '').trim()
  };
}

function cloudflareBootstrapConfig() {
  const stored = readJson(paths.cloudflareApiEdge) || {};
  const bootstrap = stored.bootstrap || {};
  return {
    originUrl: String(bootstrap.origin_url || bootstrap.originUrl || '').trim().replace(/\/$/, ''),
    apiDomain: String(bootstrap.api_domain || bootstrap.apiDomain || '').trim().toLowerCase(),
    apiWorkerName: String(bootstrap.api_worker_name || bootstrap.apiWorkerName || '').trim(),
    adminDomain: String(bootstrap.admin_domain || bootstrap.adminDomain || '').trim().toLowerCase(),
    adminWorkerName: String(bootstrap.admin_worker_name || bootstrap.adminWorkerName || '').trim()
  };
}

function cloudflarePublicFrontendProfiles() {
  const stored = readJson(paths.cloudflareApiEdge) || {};
  return Array.isArray(stored.public_frontend_profiles) ? stored.public_frontend_profiles : [];
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

async function saveBotRisk(config) {
  await writeJsonAtomic(paths.botRisk, {
    enabled: config.enabled === true,
    connection_type: config.connectionType,
    base_url: config.baseUrl,
    client_id: config.clientId,
    secret: config.secret,
    site_key: config.siteKey,
    mode: config.mode
  });
}

async function saveCloudflareApiEdge(config) {
  const stored = readJson(paths.cloudflareApiEdge) || {};
  await writeJsonAtomic(paths.cloudflareApiEdge, {
    ...stored,
    account_id: config.accountId,
    worker_name: config.workerName,
    api_token: config.apiToken
  });
}

async function saveCloudflareBootstrap(config) {
  const stored = readJson(paths.cloudflareApiEdge) || {};
  await writeJsonAtomic(paths.cloudflareApiEdge, {
    ...stored,
    bootstrap: {
      origin_url: config.originUrl,
      api_domain: config.apiDomain,
      api_worker_name: config.apiWorkerName,
      admin_domain: config.adminDomain,
      admin_worker_name: config.adminWorkerName
    }
  });
}

async function saveCloudflareCentral(config) {
  const stored = readJson(paths.cloudflareApiEdge) || {};
  await writeJsonAtomic(paths.cloudflareApiEdge, {
    ...stored,
    account_id: config.accountId,
    worker_name: config.apiWorkerName,
    api_token: config.apiToken,
    bootstrap: {
      origin_url: config.originUrl,
      api_domain: config.apiDomain,
      api_worker_name: config.apiWorkerName,
      admin_domain: config.adminDomain,
      admin_worker_name: config.adminWorkerName
    }
  });
}

async function saveCloudflarePublicFrontendProfiles(profiles) {
  const stored = readJson(paths.cloudflareApiEdge) || {};
  await writeJsonAtomic(paths.cloudflareApiEdge, {
    ...stored,
    public_frontend_profiles: profiles
  });
}

module.exports = {
  paths,
  controlCenterConfig,
  ipIntelligenceConfig,
  botRiskConfig,
  cloudflareApiEdgeConfig,
  cloudflareBootstrapConfig,
  cloudflarePublicFrontendProfiles,
  saveControlCenter,
  saveIpIntelligence,
  saveBotRisk,
  saveCloudflareApiEdge,
  saveCloudflareBootstrap,
  saveCloudflareCentral,
  saveCloudflarePublicFrontendProfiles
};
