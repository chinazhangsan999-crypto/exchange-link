'use strict';

const crypto = require('crypto');
const AnalysisService = require('./AnalysisService');
const GoogleDriveService = require('./GoogleDriveService');
const StorageService = require('./StorageService');
const { PUBLIC_API_URL } = require('../config/env');

const OAUTH_CALLBACK_PATH = '/admin/api/analysis/google-drive/oauth/callback';

function oauthRedirectUri() {
  return `${PUBLIC_API_URL}${OAUTH_CALLBACK_PATH}`;
}

let timer = null;
let running = false;

function sinceForRange(range) {
  const hours = range === '24h' ? 24 : range === '30d' ? 30 * 24 : 7 * 24;
  return new Date(Date.now() - hours * 60 * 60_000).toISOString();
}

function beijingParts(date = new Date()) {
  const values = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hourCycle: 'h23'
  }).formatToParts(date).filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
  return values;
}

function safeTimestamp(date = new Date()) {
  const p = beijingParts(date);
  const minute = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Shanghai', minute: '2-digit' }).format(date);
  return `${p.year}${p.month}${p.day}-${p.hour}${minute}`;
}

async function runBackup({ triggerType = 'manual', createdBy = 'system', force = false } = {}) {
  if (running) throw new Error('Google Drive 备份正在执行');
  running = true;
  let fileName = '';
  try {
    const settings = await StorageService.getGoogleDriveSettings({ includeCredentials: true });
    if (!settings?.configured || (!settings.enabled && !force)) throw new Error('Google Drive 个人账号尚未连接');
    const allSites = await StorageService.listEnabledSiteKeys();
    const siteKeys = settings.siteKeys.length ? settings.siteKeys.filter(key => allSites.includes(key)) : allSites;
    if (!siteKeys.length) throw new Error('没有可导出的已启用站点');
    const packageData = await AnalysisService.exportPackage({
      since: sinceForRange(settings.backupRange), minScore: settings.minScore
    }, { siteKeys });
    fileName = `${settings.filePrefix}-${safeTimestamp()}.json`;
    const content = JSON.stringify(packageData, null, 2);
    const uploaded = settings.authMode === 'personal_oauth'
      ? await GoogleDriveService.uploadPersonalJson({
        clientId: settings.oauthClientId,
        clientSecret: settings.oauthClientSecret,
        refreshToken: settings.oauthRefreshToken,
        folderId: settings.personalFolderId,
        fileName,
        content
      })
      : await GoogleDriveService.uploadJson({
        credentials: settings.credentials, folderId: settings.folderId, fileName, content
      });
    await StorageService.recordGoogleDriveBackup({ triggerType, success: true, fileId: uploaded.id, fileName, itemCount: packageData.total, createdBy });
    return { fileId: uploaded.id, fileName, itemCount: packageData.total, webViewLink: uploaded.webViewLink || '' };
  } catch (error) {
    await StorageService.recordGoogleDriveBackup({ triggerType, success: false, fileName, error: error.message, createdBy }).catch(() => {});
    throw error;
  } finally { running = false; }
}

async function testConnection() {
  const settings = await StorageService.getGoogleDriveSettings({ includeCredentials: true });
  if (!settings?.configured) throw new Error('请先连接个人 Google Drive');
  if (settings.authMode === 'personal_oauth') {
    return GoogleDriveService.testPersonalConnection({
      clientId: settings.oauthClientId,
      clientSecret: settings.oauthClientSecret,
      refreshToken: settings.oauthRefreshToken,
      folderId: settings.personalFolderId,
      connectedEmail: settings.connectedEmail
    });
  }
  return GoogleDriveService.testConnection({ credentials: settings.credentials, folderId: settings.folderId });
}

async function startPersonalOAuth(actor = 'risk-admin') {
  const settings = await StorageService.getGoogleDriveSettings({ includeCredentials: true });
  if (!settings?.oauthClientId || !settings.oauthClientSecret) {
    throw Object.assign(new Error('请先保存 Google OAuth Client ID 和 Client Secret'), { statusCode: 400 });
  }
  const verifier = crypto.randomBytes(48).toString('base64url');
  const { state } = await StorageService.createGoogleDriveOAuthState({ verifier, actor, ttlMinutes: 10 });
  return {
    authorizationUrl: GoogleDriveService.buildAuthorizationUrl({
      clientId: settings.oauthClientId,
      redirectUri: oauthRedirectUri(),
      state,
      codeChallenge: GoogleDriveService.pkceChallenge(verifier)
    }),
    expiresInMinutes: 10
  };
}

async function completePersonalOAuth({ state, code }) {
  const pending = await StorageService.consumeGoogleDriveOAuthState(state);
  if (!pending?.verifier) throw Object.assign(new Error('授权请求已过期或已被使用，请重新连接'), { statusCode: 400 });
  if (!code) throw Object.assign(new Error('Google 未返回授权码'), { statusCode: 400 });
  const settings = await StorageService.getGoogleDriveSettings({ includeCredentials: true });
  if (!settings?.oauthClientId || !settings.oauthClientSecret) throw new Error('Google OAuth 客户端配置缺失');
  try {
    const tokens = await GoogleDriveService.exchangeAuthorizationCode({
      clientId: settings.oauthClientId,
      clientSecret: settings.oauthClientSecret,
      redirectUri: oauthRedirectUri(),
      code,
      codeVerifier: pending.verifier
    });
    const account = await GoogleDriveService.getAccount(tokens.access_token);
    if (!account.email || !account.emailVerified) throw new Error('Google 账号邮箱未验证，无法连接个人网盘');
    const folder = await GoogleDriveService.ensurePersonalFolder(
      tokens.access_token,
      settings.personalFolderId,
      settings.personalFolderName
    );
    return StorageService.saveGoogleDriveOAuthConnection({
      refreshToken: tokens.refresh_token,
      email: account.email,
      folderId: folder.id,
      folderName: folder.name || settings.personalFolderName
    }, pending.actor);
  } catch (error) {
    await StorageService.recordGoogleDriveOAuthError(error.message).catch(() => {});
    throw error;
  }
}

async function disconnectPersonalOAuth(actor = 'risk-admin') {
  const settings = await StorageService.getGoogleDriveSettings({ includeCredentials: true });
  let revoked = false;
  if (settings?.oauthRefreshToken) {
    revoked = await GoogleDriveService.revokeToken(settings.oauthRefreshToken).catch(() => false);
  }
  const data = await StorageService.disconnectGoogleDriveOAuth(actor);
  return { ...data, revoked };
}

async function tick() {
  if (running) return;
  const settings = await StorageService.getGoogleDriveSettings().catch(() => null);
  if (!settings?.enabled || !settings.configured) return;
  const now = new Date();
  const parts = beijingParts(now);
  if (Number(parts.hour) !== settings.backupHourBjt) return;
  if (settings.lastBackupAt) {
    const last = beijingParts(new Date(settings.lastBackupAt));
    if (`${last.year}-${last.month}-${last.day}` === `${parts.year}-${parts.month}-${parts.day}`) return;
  }
  await runBackup({ triggerType: 'scheduled' }).catch(error => console.error('Google Drive 定时备份失败：', error.message));
}

function start() {
  if (timer) return;
  timer = setInterval(() => { void tick(); }, 15 * 60_000);
  timer.unref?.();
  setTimeout(() => { void tick(); }, 30_000).unref?.();
}

function stop() { if (timer) clearInterval(timer); timer = null; }

module.exports = {
  OAUTH_CALLBACK_PATH,
  oauthRedirectUri,
  start,
  stop,
  runBackup,
  testConnection,
  startPersonalOAuth,
  completePersonalOAuth,
  disconnectPersonalOAuth,
  sinceForRange,
  beijingParts
};
