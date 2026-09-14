'use strict';

const express = require('express');
const { get, run, all, withTransaction } = require('../config/database');
const {
  CONTROL_CENTER_ENABLED,
  CONTROL_CENTER_URL,
  CONTROL_CENTER_SITE_CREDENTIAL,
  CONTROL_CENTER_SYNC_INTERVAL_MS
} = require('../config/env');
const { issueAdminToken } = require('../middlewares/auth');
const { createControlCenterAgent } = require('../../packages/site-agent');
const { createWebringConfigApplier } = require('../../packages/site-agent/webring-adapter');
const MirrorModel = require('../models/MirrorModel');
const CacheService = require('./CacheService');

const router = express.Router();
let agent = null;
let adapter = null;

router.get('/status', (_req, res) => res.json({
  code: 200,
  data: {
    enabled: CONTROL_CENTER_ENABLED,
    controlCenterUrl: CONTROL_CENTER_ENABLED ? CONTROL_CENTER_URL : ''
  }
}));

if (CONTROL_CENTER_ENABLED) {
  adapter = createWebringConfigApplier({
    run,
    all,
    withTransaction,
    onChanged: async () => {
      await MirrorModel.syncMirrorsToPartners();
      CacheService.clearPublicCache();
    }
  });

  agent = createControlCenterAgent({
    controlCenterUrl: CONTROL_CENTER_URL,
    credential: CONTROL_CENTER_SITE_CREDENTIAL,
    intervalMs: CONTROL_CENTER_SYNC_INTERVAL_MS,
    adminPath: '/admin',
    applyConfig: snapshot => adapter.applyConfig(snapshot),
    issueAdminToken: async (_centralAdmin, context = {}) => {
      const localAdmin = await get("SELECT id, username FROM admins WHERE username='admin' ORDER BY id LIMIT 1");
      if (!localAdmin) throw new Error('导航站管理员账号不存在');
      const admin = await get('SELECT id, username, session_version FROM admins WHERE id = ?', [localAdmin.id]);
      return issueAdminToken(admin, { source: context.source || 'control_center' });
    },
    metadata: () => ({ app: 'webring-traffic-exchange', runtime: process.version }),
    onError: error => console.error('总后台 Agent：', error?.message || error)
  });
  router.use(agent.router);
}

async function initialize() {
  if (!adapter) return;
  await adapter.initialize();
}

function start() { agent?.start(); }
function stop() { agent?.stop(); }

module.exports = { router, initialize, start, stop, enabled: CONTROL_CENTER_ENABLED };
