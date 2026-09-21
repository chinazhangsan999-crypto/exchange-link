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
  res.type('text/css').set('Cache-Control', 'public, max-age=3600');
  return res.sendFile(path.join(PUBLIC_DIR, 'admin.css'));
}

function script(req, res) {
  res.type('application/javascript').set('Cache-Control', 'public, max-age=3600');
  return res.sendFile(path.join(PUBLIC_DIR, 'admin.js'));
}

function login(req, res) {
  const session = AdminAuthService.createSession(req.body?.token);
  if (!session) return res.status(401).json({ code: 401, message: '管理令牌错误' });
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

module.exports = { page, stylesheet, script, login, session, logout, overview, sites, setSiteStatus };
