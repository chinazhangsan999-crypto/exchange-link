'use strict';

const express = require('express');
const { get, run, all, withTransaction } = require('../config/database');
const { CONTROL_CENTER_SYNC_INTERVAL_MS } = require('../config/env');
const { issueAdminToken } = require('../middlewares/auth');
const { createControlCenterAgent } = require('../../packages/site-agent');
const { createWebringConfigApplier } = require('../../packages/site-agent/webring-adapter');
const MirrorModel = require('../models/MirrorModel');
const AdModel = require('../models/AdModel');
const CacheService = require('./CacheService');
const CredentialStore = require('./IntegrationCredentialStore');
const IntegrationState = require('./IntegrationStateService');
const AdminFrontendOriginService = require('./AdminFrontendOriginService');

const router = express.Router();
let agent = null;
let adapter = null;
let started = false;
let activeConfig = { url: '', credential: '' };
let lastConnectedAt = null;
let lastError = '';
let lastConfigAppliedAt = null;
let lastAppliedRevision = '';
let initialAdSyncTimer = null;

function validateConfig(input = {}) {
  const url = String(input.url || '').trim().replace(/\/$/, '');
  const credential = String(input.credential || '').trim();
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error('总后台地址格式不正确'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('总后台地址必须是 HTTPS Origin');
  }
  if (!/^\d+\.[A-Za-z0-9_-]{20,128}$/.test(credential)) throw new Error('站点接入凭据格式不正确');
  return { url, credential };
}

function buildAgent(config) {
  const adminOrigin = AdminFrontendOriginService.currentOrigin();
  return createControlCenterAgent({
    controlCenterUrl: config.url,
    credential: config.credential,
    intervalMs: CONTROL_CENTER_SYNC_INTERVAL_MS,
    adminPath: adminOrigin ? `${adminOrigin}/admin` : '/admin',
    applyConfig: async snapshot => {
      const result = await adapter.applyConfig(snapshot);
      lastConfigAppliedAt = new Date().toISOString();
      lastAppliedRevision = String(snapshot.revision || '');
      lastError = '';
      return result;
    },
    issueAdminToken: async (_centralAdmin, context = {}) => {
      const admin = await get("SELECT id, username, session_version FROM admins WHERE username='admin' ORDER BY id LIMIT 1");
      if (!admin) throw new Error('导航站管理员账号不存在');
      return issueAdminToken(admin, { source: context.source || 'control_center' });
    },
    metadata: () => ({ app: 'webring-traffic-exchange', runtime: process.version }),
    onHeartbeat: () => {
      lastConnectedAt = new Date().toISOString();
      lastError = '';
    },
    onError: error => {
      lastError = String(error?.message || error || '连接失败');
      console.error('总后台 Agent：', lastError);
    }
  });
}

async function testConfig(input) {
  const config = validateConfig(input);
  const candidate = buildAgent(config);
  try {
    const result = await candidate.heartbeat();
    lastConnectedAt = new Date().toISOString();
    lastError = '';
    return { config, result };
  } finally { candidate.destroy(); }
}

async function activate(config) {
  const normalized = validateConfig(config);
  const nextAgent = buildAgent(normalized);
  const previous = agent;
  agent = nextAgent;
  activeConfig = normalized;
  if (started) nextAgent.start();
  previous?.destroy();
}

async function enroll(input) {
  const { config } = await testConfig(input);
  await CredentialStore.saveControlCenter(config);
  await activate(config);
  return config;
}

function publicStatus() {
  const state = IntegrationState.status();
  return {
    enabled: state.enrolled,
    enrolled: state.enrolled,
    controlCenterUrl: state.enrolled ? activeConfig.url : '',
    connected: Boolean(lastConnectedAt && !lastError),
    lastConnectedAt,
    lastConfigAppliedAt,
    lastAppliedRevision,
    lastError: lastError ? '总后台暂时不可用' : ''
  };
}

function requireActiveAgent() {
  if (!agent || !IntegrationState.isControlCenterEnrolled()) throw new Error('本站尚未接入总后台');
  return agent;
}

async function syncLocalAd(row) {
  const adCode = String(row?.ad_code || '');
  const integrity = require('crypto').createHash('sha256').update(adCode).digest('hex');
  const adType = row?.ad_type === 'code' ? 'code' : 'normal';
  return requireActiveAgent().syncLocalAd(row.id, {
    title: String(row.title || ''),
    ad_type: adType,
    description: String(row.description || ''),
    image_url: adType === 'normal' ? String(row.image_url || '') : '',
    target_url: adType === 'normal' ? String(row.target_url || '') : '',
    platform: adType === 'normal' ? String(row.platform || 'all') : 'all',
    ad_code: adType === 'code' ? adCode : '',
    integrity_sha256: adType === 'code' ? integrity : '',
    render_mode: adType === 'code' && row.render_mode === 'sandbox' ? 'sandbox' : 'direct',
    ad_position: String(row.ad_position || (adType === 'code' ? 'top_float' : 'banner')),
    priority: Number(row.sort_order || 0),
    sandbox_options: (() => {
      try { return typeof row.sandbox_options === 'string' ? JSON.parse(row.sandbox_options) : (row.sandbox_options || {}); }
      catch { return {}; }
    })(),
    enabled: Number(row.status) === 1
  });
}

async function syncAllLocalAds() {
  const rows = await AdModel.listLocalAds();
  const summary = { total: rows.length, synced: 0, failed: 0, failures: [] };
  for (const row of rows) {
    try {
      await syncLocalAd(row);
      await AdModel.setEdgeSyncState(row.id, 'synced');
      summary.synced += 1;
    } catch (error) {
      const message = String(error?.message || error || '同步失败');
      await AdModel.setEdgeSyncState(row.id, 'error', message);
      summary.failed += 1;
      summary.failures.push({ id: Number(row.id), title: String(row.title || ''), message });
    }
  }
  CacheService.clearPublicCache();
  return summary;
}

function deleteLocalAd(id) { return requireActiveAgent().deleteLocalAd(id); }
const syncLocalCodeAd = syncLocalAd;
const syncAllLocalCodeAds = syncAllLocalAds;
const deleteLocalCodeAd = deleteLocalAd;

router.get('/status', (_req, res) => res.json({ code: 200, data: publicStatus() }));
router.use((req, res, next) => {
  if (!agent) return res.status(503).json({ code: 503, message: '本站尚未接入总后台', data: null });
  return agent.router(req, res, next);
});

async function initialize() {
  if (!IntegrationState.status().initialized) await IntegrationState.initialize();
  adapter = createWebringConfigApplier({
    run,
    all,
    withTransaction,
    onChanged: async () => {
      await MirrorModel.syncMirrorsToPartners();
      await syncAllLocalAds();
      CacheService.clearPublicCache();
    }
  });
  await adapter.initialize();
  if (!IntegrationState.isControlCenterEnrolled()) return;
  const config = CredentialStore.controlCenterConfig();
  try { await activate(config); }
  catch (error) {
    lastError = String(error?.message || error);
    console.error('总后台已接管，但 Agent 凭据无法加载：', lastError);
  }
}

function start() {
  started = true;
  agent?.start();
  if (!agent || initialAdSyncTimer) return;
  initialAdSyncTimer = setTimeout(() => {
    initialAdSyncTimer = null;
    syncAllLocalAds().catch(error => {
      lastError = String(error?.message || error || '本站广告初始化同步失败');
      console.error('总后台广告同步：', lastError);
    });
  }, 2500);
  initialAdSyncTimer.unref?.();
}
function stop() {
  started = false;
  if (initialAdSyncTimer) clearTimeout(initialAdSyncTimer);
  initialAdSyncTimer = null;
  agent?.stop();
}

module.exports = {
  router,
  initialize,
  start,
  stop,
  enroll,
  testConfig,
  publicStatus,
  syncLocalCodeAd,
  syncAllLocalCodeAds,
  deleteLocalCodeAd,
  syncLocalAd,
  syncAllLocalAds,
  deleteLocalAd,
  isEnrolled: IntegrationState.isControlCenterEnrolled
};
