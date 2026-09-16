'use strict';

const path = require('path');
const { ok, fail, safeApiErrorMessage } = require('../utils/http');
const CloudflareBootstrapAccessService = require('../services/CloudflareBootstrapAccessService');
const CloudflareBootstrapService = require('../services/CloudflareBootstrapService');
const CloudflarePublicFrontendService = require('../services/CloudflarePublicFrontendService');
const CloudflareApiEdgeService = require('../services/CloudflareApiEdgeService');
const FrontendOriginModel = require('../models/FrontendOriginModel');
const FrontendProxyService = require('../services/FrontendProxyService');

const PUBLIC_DIRECTORY = path.resolve(__dirname, '..', '..', 'public');

async function requireAvailable(res) {
  const status = await CloudflareBootstrapAccessService.publicStatus();
  if (!status.available) {
    res.status(404).type('text/plain').send('Not Found');
    return null;
  }
  return status;
}

async function renderSetup(req, res) {
  try {
    if (!(await requireAvailable(res))) return undefined;
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    return res.sendFile(path.join(PUBLIC_DIRECTORY, 'setup.html'));
  } catch {
    return res.status(500).type('text/plain').send('Setup unavailable');
  }
}

async function renderSetupClient(req, res) {
  try {
    if (!(await requireAvailable(res))) return undefined;
    res.setHeader('Cache-Control', 'no-store');
    return res.sendFile(path.join(PUBLIC_DIRECTORY, 'setup.js'));
  } catch {
    return res.status(500).type('text/plain').send('Setup unavailable');
  }
}

async function getStatus(req, res) {
  try {
    const status = await CloudflareBootstrapAccessService.publicStatus();
    if (!status.available) return res.status(404).end();
    res.setHeader('Cache-Control', 'no-store');
    return ok(res, status);
  } catch {
    return fail(res, '初始化状态暂不可用', 503);
  }
}

async function deploy(req, res) {
  let frontend = null;
  let previousOrigins = [];
  let originsChanged = false;
  try {
    if (!(await requireAvailable(res))) return undefined;
    const body = req.body || {};
    const sameAccount = ['1', 'true', 'on', 'yes'].includes(String(body.sameCloudflareAccount || '').toLowerCase());
    const frontendHostname = String(body.frontendHostname || '').trim();
    if (!frontendHostname) return fail(res, '请填写第一个公共前台域名');

    const result = await CloudflareBootstrapService.deploy({ ...body, confirmOverwrite: true });
    await CloudflarePublicFrontendService.saveProfile({
      id: body.frontendProfileId || 'cf-first',
      label: body.frontendLabel || '首次前台账号',
      workerPrefix: body.frontendWorkerPrefix || 'webring-public',
      accountId: sameAccount ? body.accountId : body.frontendAccountId,
      apiToken: sameAccount ? body.apiToken : body.frontendApiToken
    }, { skipInitialization: true });

    previousOrigins = await FrontendOriginModel.listAllOrigins();
    frontend = await CloudflarePublicFrontendService.createDedicatedFrontend(frontendHostname);
    const origin = `https://${frontend.hostname}`;
    const nextByOrigin = new Map(previousOrigins.map(item => [item.origin, {
      origin: item.origin,
      enabled: Number(item.enabled) === 1,
      expiresAt: item.expires_at || null
    }]));
    nextByOrigin.set(origin, { origin, enabled: true, expiresAt: null });
    const nextOrigins = [...nextByOrigin.values()];
    const edgeSync = await CloudflareApiEdgeService.syncAllowedOrigins(nextOrigins);
    if (!edgeSync.synchronized) throw new Error('API Edge 白名单尚未配置，无法安全开放第一个前台');
    await FrontendOriginModel.replaceOrigins(nextOrigins);
    FrontendProxyService.clearAllowedOriginCache();
    originsChanged = true;

    const health = await CloudflarePublicFrontendService.checkHealth(frontend.hostname);
    await CloudflarePublicFrontendService.finalizeDedicatedFrontend(frontend, health);
    await CloudflareBootstrapAccessService.consume();
    res.setHeader('Cache-Control', 'no-store');
    return ok(res, {
      ...result,
      frontend: {
        hostname: frontend.hostname,
        url: `https://${frontend.hostname}/`,
        service: frontend.workerName,
        zone: frontend.zone,
        health
      },
      edgeSync,
      note: health.healthy
        ? '中央入口与第一个公共前台均已可访问'
        : '部署已完成；第一个公共前台正在等待 Cloudflare DNS 或证书生效'
    }, '首次建站完成，初始化入口已永久关闭');
  } catch (error) {
    if (originsChanged) {
      await CloudflareApiEdgeService.syncAllowedOrigins(previousOrigins).catch(rollbackError => {
        console.error('回滚首次建站 API Edge 白名单失败：', rollbackError);
      });
      await FrontendOriginModel.replaceOrigins(previousOrigins).then(() => {
        FrontendProxyService.clearAllowedOriginCache();
      }).catch(rollbackError => {
        console.error('回滚首次建站本地白名单失败：', rollbackError);
      });
    }
    if (frontend) {
      await CloudflarePublicFrontendService.rollbackDedicatedFrontend(frontend, error.message).catch(rollbackError => {
        console.error('回滚首次建站公共前台失败：', rollbackError);
      });
    }
    console.error(`一次性 Cloudflare 初始化失败：${String(error?.message || 'unknown')}`);
    return fail(res, safeApiErrorMessage(error, '部署失败，请核对 Cloudflare Token 权限、三个域名归属和源站地址'), 400);
  }
}

module.exports = { renderSetup, renderSetupClient, getStatus, deploy };
