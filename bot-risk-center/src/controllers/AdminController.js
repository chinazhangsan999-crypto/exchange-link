'use strict';

const path = require('path');
const AdminAuthService = require('../services/AdminAuthService');
const StorageService = require('../services/StorageService');
const AlertService = require('../services/AlertService');
const MaintenanceService = require('../services/MaintenanceService');
const AnalysisService = require('../services/AnalysisService');
const DriveBackupService = require('../services/DriveBackupService');
const RuleBackupService = require('../services/RuleBackupService');
const { PUBLIC_API_URL } = require('../config/env');

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
  const session = await AdminAuthService.createSession(req.body?.username, req.body?.password, {
    sourceIp: source, userAgent: req.get('user-agent') || ''
  });
  if (!session) return res.status(401).json({ code: 401, message: '账号或密码错误' });
  res.cookie(AdminAuthService.COOKIE_NAME, session.sessionId, AdminAuthService.cookieOptions());
  return res.json({ code: 200, data: { csrfToken: session.csrfToken, expiresAt: session.expiresAt } });
}

async function session(req, res) {
  const current = await AdminAuthService.sessionFromRequest(req);
  if (!current) return res.status(401).json({ code: 401, message: 'Unauthorized' });
  return res.json({ code: 200, data: { csrfToken: current.csrfToken, expiresAt: current.expiresAt } });
}

async function logout(req, res) {
  await AdminAuthService.destroySession(req);
  res.clearCookie(AdminAuthService.COOKIE_NAME, { ...AdminAuthService.cookieOptions(), maxAge: undefined });
  return res.json({ code: 200, message: '已退出' });
}

async function overview(req, res) {
  return res.json({ code: 200, data: await StorageService.getAdminOverview(String(req.query.range || '24h')) });
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
function actor(req) { return req.riskAdmin?.username || 'risk-admin'; }

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
  return res.json({ code: 200, data: await StorageService.getRiskSummary(String(req.query.siteKey || ''), String(req.query.range || '24h')) });
}

async function suspects(req, res) {
  return res.json({ code: 200, data: await StorageService.listSuspects({
    siteKey: String(req.query.siteKey || ''), page: req.query.page,
    limit: req.query.limit, minScore: req.query.minScore, range: req.query.range
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
  const permanent = req.body?.permanent === true;
  const applyToAllSites = req.body?.applyToAllSites === true;
  const ruleSignal = String(req.body?.ruleSignal || '').trim();
  if (!validSiteKey(siteKey) || !validVisitorHash(visitorHash)
    || !['allow', 'observe', 'silent_challenge', 'strong_challenge', 'deny'].includes(action)
    || !reason || (applyToAllSites && !/^[a-z0-9_-]{2,64}$/i.test(ruleSignal))) {
    return res.status(400).json({ code: 400, message: '处置动作、原因或全站规则信号无效' });
  }
  const data = await StorageService.applyManualDecision(
    siteKey, visitorHash, action, req.body?.durationMinutes, reason, actor(req), permanent,
    applyToAllSites ? { signal: ruleSignal } : null
  );
  if (applyToAllSites) RuleBackupService.scheduleChangedBackup();
  return res.json({
    code: 200,
    data,
    message: applyToAllSites ? '人工处置及全站同类规则已生效' : '人工处置已生效'
  });
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
  input.permanent = input.permanent === true;
  input.mode = input.mode === 'shadow' ? 'shadow' : 'enforce';
  const validRuleSite = input.siteKey === '*' || validSiteKey(input.siteKey);
  if (!validRuleSite || !/^[a-z0-9_-]{2,64}$/i.test(String(input.signal || ''))
    || !['allow', 'observe', 'silent_challenge', 'strong_challenge', 'deny'].includes(String(input.action || ''))) {
    return res.status(400).json({ code: 400, message: '规则参数无效' });
  }
  const id = await StorageService.createSignalRule(input, actor(req));
  RuleBackupService.scheduleChangedBackup();
  return res.json({ code: 200, data: { id }, message: '信号规则已创建' });
}

async function setRuleStatus(req, res) {
  if (typeof req.body?.enabled !== 'boolean') return res.status(400).json({ code: 400, message: '参数无效' });
  const data = await StorageService.setSignalRuleEnabled(Number(req.params.id), req.body.enabled, actor(req));
  if (!data) return res.status(404).json({ code: 404, message: '规则不存在' });
  RuleBackupService.scheduleChangedBackup();
  return res.json({ code: 200, data, message: data.enabled ? '规则已启用' : '规则已停用' });
}

async function deleteRule(req, res) {
  const removed = await StorageService.deleteSignalRule(Number(req.params.id), actor(req));
  if (!removed) return res.status(404).json({ code: 404, message: '规则不存在' });
  RuleBackupService.scheduleChangedBackup();
  return res.json({ code: 200, message: '规则已删除' });
}

async function ruleBackupSettings(req, res) {
  return res.json({ code: 200, data: await StorageService.getRuleBackupSettings() });
}

async function saveRuleBackupSettings(req, res) {
  const input = req.body || {};
  const current = await StorageService.getRuleBackupSettings();
  if (typeof input.enabled !== 'boolean' || typeof input.automaticOnChange !== 'boolean') {
    return res.status(400).json({ code: 400, message: '备份开关参数无效' });
  }
  if (input.enabled && !String(input.telegramChatId || '').trim()) {
    return res.status(400).json({ code: 400, message: '启用备份时必须填写独立 Backup Bot 的 Chat ID' });
  }
  if (input.enabled && !String(input.telegramToken || '').trim() && !current?.telegramConfigured) {
    return res.status(400).json({ code: 400, message: '启用备份时必须填写独立 Backup Bot Token' });
  }
  const data = await StorageService.saveRuleBackupSettings(input, actor(req));
  return res.json({ code: 200, data, message: '人工规则备份设置已保存' });
}

async function ruleBackupStatus(req, res) {
  return res.json({ code: 200, data: await RuleBackupService.status() });
}

async function testRuleBackup(req, res) {
  const data = await RuleBackupService.testConnection();
  return res.json({ code: 200, data, message: '独立 Backup Bot 测试成功' });
}

async function runRuleBackup(req, res) {
  const data = await RuleBackupService.runBackup({ triggerType: 'manual', createdBy: actor(req), force: true });
  return res.json({ code: 200, data, message: `人工规则备份完成，共 ${data.partsTotal} 个加密分片` });
}

async function retryRuleBackup(req, res) {
  const data = await RuleBackupService.retryFailed();
  return res.json({ code: 200, data, message: '失败的人工规则备份已重试完成' });
}

async function audits(req, res) {
  return res.json({ code: 200, data: await StorageService.listAdminAudits(req.query.limit) });
}

function adminRequestContext(req) {
  return {
    sourceIp: String(req.get('CF-Connecting-IP') || req.ip || 'unknown'),
    userAgent: String(req.get('user-agent') || '')
  };
}

async function detectionCapabilities(req, res) {
  return res.json({ code: 200, data: await StorageService.getDetectionCapabilities(String(req.query.range || '24h')) });
}

async function detectionQuality(req, res) {
  return res.json({ code: 200, data: await StorageService.getDetectionQuality(String(req.query.range || '24h')) });
}

async function pipelineHealth(req, res) {
  return res.json({ code: 200, data: await StorageService.getPipelineHealth() });
}

async function identityEntries(req, res) {
  return res.json({ code: 200, data: await StorageService.listIdentityEntries() });
}

async function saveIdentityEntry(req, res) {
  const input = req.body || {};
  if (!['allow', 'block'].includes(String(input.listType || ''))
    || !(input.siteKey === '*' || validSiteKey(input.siteKey))
    || !['visitor', 'bot_identity', 'ua', 'ja4', 'asn'].includes(String(input.subjectType || ''))
    || !String(input.subjectHash || '').trim() || String(input.subjectHash).length > 300) {
    return res.status(400).json({ code: 400, message: '名单参数无效' });
  }
  const id = await StorageService.saveIdentityEntry({
    listType: input.listType, siteKey: input.siteKey, subjectType: input.subjectType,
    subjectHash: String(input.subjectHash).trim(), reason: String(input.reason || '').trim().slice(0, 300),
    durationMinutes: input.permanent === true ? 0 : Math.max(1, Math.min(525600, Number(input.durationMinutes) || 60))
  }, actor(req));
  return res.json({ code: 200, data: { id }, message: '名单项已保存' });
}

async function deleteIdentityEntry(req, res) {
  const listType = String(req.params.listType || '');
  if (!['allow', 'block'].includes(listType)) return res.status(400).json({ code: 400, message: '名单类型无效' });
  const removed = await StorageService.deleteIdentityEntry(listType, Number(req.params.id), actor(req));
  return removed ? res.json({ code: 200, message: '名单项已删除' })
    : res.status(404).json({ code: 404, message: '名单项不存在' });
}

async function ruleRevisions(req, res) {
  return res.json({ code: 200, data: await StorageService.listRuleRevisions(req.query.limit) });
}

async function policies(req, res) {
  return res.json({ code: 200, data: await StorageService.listPolicies() });
}

async function createPolicy(req, res) {
  const input = req.body || {};
  const thresholds = input.thresholds || {};
  const values = ['observe', 'silentChallenge', 'strongChallenge', 'deny'].map(key => Number(thresholds[key]));
  if (!String(input.name || '').trim() || !/^[A-Za-z0-9_.-]{3,80}$/.test(String(input.version || ''))
    || values.some(value => !Number.isInteger(value) || value < 0 || value > 100)
    || !(values[0] < values[1] && values[1] < values[2] && values[2] < values[3])) {
    return res.status(400).json({ code: 400, message: '策略名称、版本或递增阈值无效' });
  }
  const id = await StorageService.createPolicy({ name: String(input.name).trim().slice(0, 120),
    version: String(input.version), thresholds: { observe: values[0], silentChallenge: values[1], strongChallenge: values[2], deny: values[3] } }, actor(req));
  return res.json({ code: 200, data: { id }, message: '策略草稿版本已创建，尚未启用' });
}

async function activatePolicy(req, res) {
  const data = await StorageService.activatePolicy(Number(req.params.id), actor(req));
  return data ? res.json({ code: 200, data, message: `策略 ${data.version} 已启用` })
    : res.status(404).json({ code: 404, message: '策略不存在' });
}

async function securityOverview(req, res) {
  const [credential, sessions] = await Promise.all([
    StorageService.getAdminCredential(), AdminAuthService.listSessions(req.riskAdmin)
  ]);
  return res.json({ code: 200, data: {
    account: { username: credential?.username || req.riskAdmin.username, passwordChangedAt: credential?.passwordChangedAt || null },
    sessions
  } });
}

async function changeCredentials(req, res) {
  try {
    const result = await AdminAuthService.changeCredentials(
      req.riskAdmin, req.body?.currentPassword, req.body?.username, req.body?.newPassword,
      adminRequestContext(req)
    );
    if (!result) return res.status(403).json({ code: 403, message: '当前密码不正确' });
    res.clearCookie(AdminAuthService.COOKIE_NAME, { ...AdminAuthService.cookieOptions(), maxAge: undefined });
    return res.json({ code: 200, data: result, message: '账号密码已修改，所有登录设备已退出，请重新登录' });
  } catch (error) {
    return res.status(400).json({ code: 400, message: error.message });
  }
}

async function revokeSession(req, res) {
  const data = await AdminAuthService.revokeSession(req.riskAdmin, Number(req.params.id), adminRequestContext(req));
  if (!data) return res.status(404).json({ code: 404, message: '会话不存在或已失效' });
  if (data.current) res.clearCookie(AdminAuthService.COOKIE_NAME, { ...AdminAuthService.cookieOptions(), maxAge: undefined });
  return res.json({ code: 200, data, message: data.current ? '当前会话已撤销' : '指定会话已撤销' });
}

async function revokeOtherSessions(req, res) {
  const count = await AdminAuthService.revokeOtherSessions(req.riskAdmin, adminRequestContext(req));
  return res.json({ code: 200, data: { count }, message: `已下线 ${count} 个其他会话` });
}

async function revokeAllSessions(req, res) {
  const count = await AdminAuthService.revokeAllSessions(req.riskAdmin, adminRequestContext(req));
  res.clearCookie(AdminAuthService.COOKIE_NAME, { ...AdminAuthService.cookieOptions(), maxAge: undefined });
  return res.json({ code: 200, data: { count }, message: `已下线全部 ${count} 个会话` });
}

async function alertSettings(req, res) {
  return res.json({ code: 200, data: await StorageService.getAlertSettings() });
}

async function saveAlertSettings(req, res) {
  const input = req.body || {};
  const current = await StorageService.getAlertSettings();
  if (typeof input.enabled !== 'boolean'
    || typeof input.telegramEnabled !== 'boolean'
    || typeof input.barkEnabled !== 'boolean') {
    return res.status(400).json({ code: 400, message: '告警开关参数无效' });
  }
  if (input.telegramEnabled && !String(input.telegramChatId || '').trim()) {
    return res.status(400).json({ code: 400, message: '启用 Telegram 时必须填写 Chat ID' });
  }
  if (input.telegramEnabled && !String(input.telegramToken || '').trim() && !current?.telegramConfigured) {
    return res.status(400).json({ code: 400, message: '启用 Telegram 时必须填写 Bot Token' });
  }
  if (input.barkEnabled && !/^https:\/\//i.test(String(input.barkServerUrl || ''))) {
    return res.status(400).json({ code: 400, message: 'Bark 服务地址必须使用 HTTPS' });
  }
  if (input.barkEnabled && !String(input.barkDeviceKey || '').trim() && !current?.barkConfigured) {
    return res.status(400).json({ code: 400, message: '启用 Bark 时必须填写 Device Key' });
  }
  const data = await StorageService.saveAlertSettings(input, actor(req));
  return res.json({ code: 200, data, message: '告警配置已保存' });
}

async function alertActivity(req, res) {
  return res.json({ code: 200, data: await StorageService.listAlertActivity(req.query.limit) });
}

async function testAlert(req, res) {
  const provider = String(req.params.provider || '');
  if (!['telegram', 'bark'].includes(provider)) {
    return res.status(400).json({ code: 400, message: '不支持的推送渠道' });
  }
  const data = await AlertService.test(provider);
  return res.json({ code: 200, data, message: `${provider === 'telegram' ? 'Telegram' : 'Bark'} 测试推送成功` });
}

async function maintenanceProjects(req, res) {
  return res.json({ code: 200, data: await StorageService.listMaintenanceProjects() });
}

async function maintenanceSites(req, res) {
  return res.json({ code: 200, data: await StorageService.listSiteMaintenanceMatrix() });
}

async function checkMaintenanceProjects(req, res) {
  const data = await MaintenanceService.checkUpstreams({ force: true });
  return res.json({ code: 200, data, message: `已检查 ${data.checked || 0} 个上游项目，发现 ${data.updates || 0} 个待跟进版本` });
}

async function setMaintenanceProjectStatus(req, res) {
  const projectKey = String(req.params.projectKey || '');
  const action = String(req.body?.action || '');
  if (!/^[a-z0-9_-]{2,64}$/i.test(projectKey) || !['followed', 'ignored', 'reset'].includes(action)) {
    return res.status(400).json({ code: 400, message: '项目或操作无效' });
  }
  const data = await StorageService.setMaintenanceProjectStatus(projectKey, action, actor(req));
  if (!data) return res.status(404).json({ code: 404, message: '项目不存在' });
  const messages = { followed: '已记录为完成评估/跟进', ignored: '已忽略当前版本', reset: '已重置跟进状态' };
  return res.json({ code: 200, data, message: messages[action] });
}

async function createMaintenanceToken(req, res) {
  const data = await StorageService.createMaintenanceToken(actor(req), 15, 50);
  return res.json({
    code: 200,
    data: {
      ...data,
      snapshotUrl: `${PUBLIC_API_URL}/v1/maintenance/snapshot`,
      upstreamsUrl: `${PUBLIC_API_URL}/v1/maintenance/upstreams`
    },
    message: '15 分钟只读令牌已生成，仅显示一次'
  });
}

async function createAnalysisToken(req, res) {
  const requested = Array.isArray(req.body?.siteKeys) ? req.body.siteKeys : [];
  const siteKeys = requested.length ? requested : await StorageService.listEnabledSiteKeys();
  const data = await StorageService.createAnalysisToken({
    siteKeys, scopes: ['suspects:list', 'suspects:detail'], ttlMinutes: 15, maxUses: 20
  }, actor(req));
  return res.json({
    code: 200,
    data: { ...data, listUrl: `${PUBLIC_API_URL}/v1/analysis/suspects`, detailBaseUrl: `${PUBLIC_API_URL}/v1/analysis/suspects` },
    message: '15 分钟只读分析令牌已生成，仅显示一次'
  });
}

async function exportAnalysis(req, res) {
  const enabledSites = await StorageService.listEnabledSiteKeys();
  const requested = Array.isArray(req.body?.siteKeys) ? req.body.siteKeys.map(String) : [];
  const siteKeys = requested.length ? requested.filter(key => enabledSites.includes(key)) : enabledSites;
  if (!siteKeys.length) return res.status(400).json({ code: 400, message: '没有可导出的站点' });
  const packageData = await AnalysisService.exportPackage({
    siteKey: String(req.body?.siteKey || ''), minScore: req.body?.minScore,
    since: req.body?.since, subjects: Array.isArray(req.body?.subjects) ? req.body.subjects : [], selectedOnly: req.body?.selectedOnly === true
  }, { siteKeys });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  res.set({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Disposition': `attachment; filename="risk-analysis-${stamp}.json"`,
    'Cache-Control': 'no-store'
  });
  return res.send(JSON.stringify(packageData, null, 2));
}

async function googleDriveSettings(req, res) {
  return res.json({
    code: 200,
    data: {
      ...await StorageService.getGoogleDriveSettings(),
      oauthCallbackUrl: DriveBackupService.oauthRedirectUri()
    }
  });
}

async function saveGoogleDriveSettings(req, res) {
  const data = await StorageService.saveGoogleDriveSettings(req.body || {}, actor(req));
  return res.json({ code: 200, data, message: 'Google Drive 备份设置已保存' });
}

async function testGoogleDrive(req, res) {
  const data = await DriveBackupService.testConnection();
  return res.json({ code: 200, data, message: 'Google Drive 连接测试成功，测试文件已清理' });
}

async function backupGoogleDrive(req, res) {
  const data = await DriveBackupService.runBackup({ triggerType: 'manual', createdBy: actor(req), force: true });
  return res.json({ code: 200, data, message: `已备份 ${data.itemCount} 条脱敏分析记录` });
}

async function connectGoogleDrive(req, res) {
  const data = await DriveBackupService.startPersonalOAuth(actor(req));
  return res.json({ code: 200, data, message: 'Google 个人账号授权已准备好' });
}

async function googleDriveOAuthCallback(req, res) {
  try {
    if (req.query.error) {
      await DriveBackupService.completePersonalOAuth({ state: req.query.state, code: '' });
    } else {
      await DriveBackupService.completePersonalOAuth({ state: req.query.state, code: req.query.code });
    }
    return res.redirect(303, '/admin?drive=connected#suspects');
  } catch (error) {
    console.error('Google Drive 个人账号授权失败：', error.message);
    await StorageService.recordGoogleDriveOAuthError(error.message).catch(() => {});
    return res.redirect(303, '/admin?drive=error#suspects');
  }
}

async function disconnectGoogleDrive(req, res) {
  const data = await DriveBackupService.disconnectPersonalOAuth(actor(req));
  return res.json({
    code: 200,
    data,
    message: data.revoked ? '已断开个人 Google Drive 并撤销授权' : '已断开个人 Google Drive'
  });
}

module.exports = {
  page, stylesheet, script, login, session, logout, overview, sites, setSiteStatus,
  saveIntegration, setSiteControls, setClientStatus, rotateClientSecret,
  riskSummary, suspects, suspectDetail, setSuspectAction, clearSuspectAction,
  rules, previewRule, createRule, setRuleStatus, deleteRule, ruleRevisions, policies, createPolicy, activatePolicy, audits,
  detectionCapabilities, detectionQuality, pipelineHealth, identityEntries, saveIdentityEntry, deleteIdentityEntry,
  securityOverview, changeCredentials, revokeSession, revokeOtherSessions, revokeAllSessions,
  alertSettings, saveAlertSettings, alertActivity, testAlert,
  ruleBackupSettings, saveRuleBackupSettings, ruleBackupStatus, testRuleBackup, runRuleBackup, retryRuleBackup,
  maintenanceProjects, maintenanceSites, checkMaintenanceProjects, setMaintenanceProjectStatus,
  createMaintenanceToken, createAnalysisToken, exportAnalysis,
  googleDriveSettings, saveGoogleDriveSettings, testGoogleDrive, backupGoogleDrive,
  connectGoogleDrive, googleDriveOAuthCallback, disconnectGoogleDrive
};
