'use strict';

const path = require('path');
const AdminAuthService = require('../services/AdminAuthService');
const StorageService = require('../services/StorageService');

const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');

function page(req, res) {
  res.set('Cache-Control', 'no-store');
  return res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
}

function stylesheet(req, res) {
  res.type('text/css').set('Cache-Control', 'no-store');
  return res.sendFile(path.join(PUBLIC_DIR, 'admin.css'));
}

function script(req, res) {
  res.type('application/javascript').set('Cache-Control', 'no-store');
  return res.sendFile(path.join(PUBLIC_DIR, 'admin.js'));
}

async function login(req, res) {
  const source = String(req.get('CF-Connecting-IP') || req.ip || 'unknown');
  const session = await AdminAuthService.createSession(req.body?.username, req.body?.password, source);
  if (!session) return res.status(401).json({ code: 401, message: '账号或密码错误' });
  res.cookie(AdminAuthService.COOKIE_NAME, session.sessionId, AdminAuthService.cookieOptions());
  return res.json({ code: 200, data: { csrfToken: session.csrfToken, expiresAt: session.expiresAt } });
}

function session(req, res) {
  const current = AdminAuthService.sessionFromRequest(req);
  if (!current) return res.status(401).json({ code: 401, message: 'Unauthorized' });
  return res.json({ code: 200, data: { csrfToken: current.csrfToken, expiresAt: current.expiresAt } });
}

function logout(req, res) {
  AdminAuthService.destroySession(req);
  res.clearCookie(AdminAuthService.COOKIE_NAME, { ...AdminAuthService.cookieOptions(), maxAge: undefined });
  return res.json({ code: 200, message: '已退出' });
}

async function overview(req, res) {
  return res.json({ code: 200, data: await StorageService.getAdminOverview() });
}

async function sites(req, res) {
  return res.json({ code: 200, data: await StorageService.listAdminSites() });
}

async function setSiteStatus(req, res) {
  const siteKey = String(req.params.siteKey || '');
  if (!/^[A-Za-z0-9_-]{3,64}$/.test(siteKey) || typeof req.body?.enabled !== 'boolean') {
    return res.status(400).json({ code: 400, message: '参数无效' });
  }
  const site = await StorageService.setSiteEnabled(siteKey, req.body.enabled, 'risk-admin');
  if (!site) return res.status(404).json({ code: 404, message: '站点不存在' });
  return res.json({ code: 200, data: site, message: site.enabled ? '对接已开启' : '对接已关闭' });
}

function validSiteKey(value) { return /^[A-Za-z0-9_-]{3,64}$/.test(String(value || '')); }
function validVisitorHash(value) { return /^[a-f0-9]{32,128}$/i.test(String(value || '')); }
function actor(req) { return req.admin?.username || 'risk-admin'; }

async function saveIntegration(req, res) {
  const input = req.body || {};
  if (!validSiteKey(input.siteKey)
    || !/^[A-Za-z0-9_-]{3,64}$/.test(String(input.clientId || ''))
    || !String(input.name || '').trim()
    || !Array.isArray(input.urls)
    || input.urls.length < 1
    || input.urls.length > 100) {
    return res.status(400).json({ code: 400, message: '站点名称、标识、客户端标识或网址清单无效' });
  }
  const data = await StorageService.saveIntegration({
    ...input,
    name: String(input.name).trim().slice(0, 120),
    clientName: String(input.clientName || '').trim().slice(0, 120)
  }, actor(req));
  return res.json({ code: 200, data, message: data.secret ? '对接已创建，请立即保存一次性密钥' : '对接配置已更新' });
}

async function setSiteControls(req, res) {
  const siteKey = String(req.params.siteKey || '');
  if (!validSiteKey(siteKey) || typeof req.body?.collectionEnabled !== 'boolean'
    || typeof req.body?.enforcementEnabled !== 'boolean') {
    return res.status(400).json({ code: 400, message: '参数无效' });
  }
  const data = await StorageService.setSiteControls(siteKey, req.body, actor(req));
  if (!data) return res.status(404).json({ code: 404, message: '站点不存在' });
  return res.json({ code: 200, data, message: '采集与执行策略已更新' });
}

async function setClientStatus(req, res) {
  if (typeof req.body?.enabled !== 'boolean') return res.status(400).json({ code: 400, message: '参数无效' });
  const data = await StorageService.setClientEnabled(String(req.params.clientId || ''), req.body.enabled, actor(req));
  if (!data) return res.status(404).json({ code: 404, message: '客户端不存在' });
  return res.json({ code: 200, data, message: data.enabled ? '数据线路已开启' : '数据线路已关闭' });
}

async function rotateClientSecret(req, res) {
  const data = await StorageService.rotateClientSecret(String(req.params.clientId || ''), actor(req));
  if (!data) return res.status(404).json({ code: 404, message: '客户端不存在' });
  return res.json({ code: 200, data, message: '密钥已轮换，旧密钥立即失效' });
}

async function riskSummary(req, res) {
  return res.json({ code: 200, data: await StorageService.getRiskSummary(String(req.query.siteKey || '')) });
}

async function suspects(req, res) {
  return res.json({ code: 200, data: await StorageService.listSuspects({
    siteKey: String(req.query.siteKey || ''), page: req.query.page,
    limit: req.query.limit, minScore: req.query.minScore
  }) });
}

async function suspectDetail(req, res) {
  const siteKey = String(req.params.siteKey || '');
  const visitorHash = String(req.params.visitorHash || '').toLowerCase();
  if (!validSiteKey(siteKey) || !validVisitorHash(visitorHash)) {
    return res.status(400).json({ code: 400, message: '参数无效' });
  }
  const data = await StorageService.getSuspectDetail(siteKey, visitorHash);
  if (!data) return res.status(404).json({ code: 404, message: '记录不存在' });
  return res.json({ code: 200, data });
}

async function setSuspectAction(req, res) {
  const siteKey = String(req.params.siteKey || '');
  const visitorHash = String(req.params.visitorHash || '').toLowerCase();
  const action = String(req.body?.action || '');
  const reason = String(req.body?.reason || '').trim().slice(0, 300);
  if (!validSiteKey(siteKey) || !validVisitorHash(visitorHash)
    || !['allow', 'observe', 'silent_challenge', 'strong_challenge', 'deny'].includes(action)
    || !reason) return res.status(400).json({ code: 400, message: '处置动作或原因无效' });
  const data = await StorageService.applyManualDecision(
    siteKey, visitorHash, action, req.body?.durationMinutes, reason, actor(req)
  );
  return res.json({ code: 200, data, message: '人工处置已生效' });
}

async function clearSuspectAction(req, res) {
  const siteKey = String(req.params.siteKey || '');
  const visitorHash = String(req.params.visitorHash || '').toLowerCase();
  if (!validSiteKey(siteKey) || !validVisitorHash(visitorHash)) {
    return res.status(400).json({ code: 400, message: '参数无效' });
  }
  const removed = await StorageService.clearManualDecision(siteKey, visitorHash, actor(req));
  return res.json({ code: 200, data: { removed }, message: '人工处置已解除' });
}

async function rules(req, res) {
  return res.json({ code: 200, data: await StorageService.listSignalRules() });
}

async function previewRule(req, res) {
  return res.json({ code: 200, data: await StorageService.previewSignalRule(
    String(req.query.siteKey || ''), String(req.query.signal || '')
  ) });
}

async function createRule(req, res) {
  const input = req.body || {};
  if (!validSiteKey(input.siteKey) || !/^[a-z0-9_-]{2,64}$/i.test(String(input.signal || ''))
    || !['allow', 'observe', 'silent_challenge', 'strong_challenge', 'deny'].includes(String(input.action || ''))) {
    return res.status(400).json({ code: 400, message: '规则参数无效' });
  }
  const id = await StorageService.createSignalRule(input, actor(req));
  return res.json({ code: 200, data: { id }, message: '信号规则已创建' });
}

async function setRuleStatus(req, res) {
  if (typeof req.body?.enabled !== 'boolean') return res.status(400).json({ code: 400, message: '参数无效' });
  const data = await StorageService.setSignalRuleEnabled(Number(req.params.id), req.body.enabled, actor(req));
  if (!data) return res.status(404).json({ code: 404, message: '规则不存在' });
  return res.json({ code: 200, data, message: data.enabled ? '规则已启用' : '规则已停用' });
}

async function deleteRule(req, res) {
  const removed = await StorageService.deleteSignalRule(Number(req.params.id), actor(req));
  if (!removed) return res.status(404).json({ code: 404, message: '规则不存在' });
  return res.json({ code: 200, message: '规则已删除' });
}

async function audits(req, res) {
  return res.json({ code: 200, data: await StorageService.listAdminAudits(req.query.limit) });
}

module.exports = {
  page, stylesheet, script, login, session, logout, overview, sites, setSiteStatus,
  saveIntegration, setSiteControls, setClientStatus, rotateClientSecret,
  riskSummary, suspects, suspectDetail, setSuspectAction, clearSuspectAction,
  rules, previewRule, createRule, setRuleStatus, deleteRule, audits
};
