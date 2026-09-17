'use strict';

const express = require('express');
const { get, run, all, withTransaction } = require('../config/database');
const { CONTROL_CENTER_SYNC_INTERVAL_MS } = require('../config/env');
const { issueAdminToken } = require('../middlewares/auth');
const { createControlCenterAgent } = require('../../packages/site-agent');
const { createWebringConfigApplier } = require('../../packages/site-agent/webring-adapter');
const MirrorModel = require('../models/MirrorModel');
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
    applyConfig: snapshot => adapter.applyConfig(snapshot),
    issueAdminToken: async (_centralAdmin, context = {}) => {
      const admin = await get("SELECT id, username, session_version FROM admins WHERE username='admin' ORDER BY id LIMIT 1");
      if (!admin) throw new Error('导航站管理员账号不存在');
      return issueAdminToken(admin, { source: context.source || 'control_center' });
    },
    metadata: () => ({ app: 'webring-traffic-exchange', runtime: process.version }),
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
    lastError: lastError ? '总后台暂时不可用' : ''
  };
}

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

function start() { started = true; agent?.start(); }
function stop() { started = false; agent?.stop(); }

module.exports = {
  router,
  initialize,
  start,
  stop,
  enroll,
  testConfig,
  publicStatus,
  isEnrolled: IntegrationState.isControlCenterEnrolled
};
