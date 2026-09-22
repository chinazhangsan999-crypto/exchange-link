'use strict';

const crypto = require('crypto');

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const REVOKE_URL = 'https://oauth2.googleapis.com/revoke';
const USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';
const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive.file';
const DRIVE_API = 'https://www.googleapis.com/drive/v3/files';
const DRIVE_UPLOAD = 'https://www.googleapis.com/upload/drive/v3/files';
const FOLDER_MIME = 'application/vnd.google-apps.folder';

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function pkceChallenge(verifier) {
  return crypto.createHash('sha256').update(String(verifier)).digest('base64url');
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try { return await fetch(url, { ...options, signal: controller.signal }); }
  finally { clearTimeout(timer); }
}

async function jsonResponse(response, label) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = String(data.error_description || data.error?.message || data.error || '').slice(0, 240);
    throw new Error(`${label}（${response.status}${detail ? `：${detail}` : ''}）`);
  }
  return data;
}

function buildAuthorizationUrl({ clientId, redirectUri, state, codeChallenge }) {
  const url = new URL(AUTH_URL);
  url.search = new URLSearchParams({
    client_id: String(clientId),
    redirect_uri: String(redirectUri),
    response_type: 'code',
    scope: `openid email ${DRIVE_SCOPE}`,
    access_type: 'offline',
    include_granted_scopes: 'true',
    prompt: 'consent',
    state: String(state),
    code_challenge: String(codeChallenge),
    code_challenge_method: 'S256'
  }).toString();
  return url.toString();
}

async function exchangeAuthorizationCode({ clientId, clientSecret, redirectUri, code, codeVerifier }) {
  const response = await fetchWithTimeout(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      code,
      code_verifier: codeVerifier
    })
  });
  const data = await jsonResponse(response, 'Google 个人账号授权失败');
  if (!data.access_token || !data.refresh_token) {
    throw new Error('Google 未返回离线刷新令牌，请撤销旧授权后重新连接');
  }
  return data;
}

async function personalAccessToken({ clientId, clientSecret, refreshToken }) {
  if (!clientId || !clientSecret || !refreshToken) throw new Error('Google Drive 个人账号授权不完整');
  const response = await fetchWithTimeout(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  });
  const data = await jsonResponse(response, 'Google Drive 访问令牌刷新失败');
  if (!data.access_token) throw new Error('Google Drive 未返回访问令牌');
  return data.access_token;
}

async function getAccount(accessToken) {
  const response = await fetchWithTimeout(USERINFO_URL, {
    headers: { authorization: `Bearer ${accessToken}` }
  });
  const data = await jsonResponse(response, 'Google 账号信息读取失败');
  return { email: String(data.email || ''), emailVerified: data.email_verified === true };
}

async function getFolder(accessToken, folderId) {
  if (!folderId) return null;
  const query = new URLSearchParams({ fields: 'id,name,mimeType,trashed,webViewLink' });
  const response = await fetchWithTimeout(`${DRIVE_API}/${encodeURIComponent(folderId)}?${query}`, {
    headers: { authorization: `Bearer ${accessToken}` }
  });
  if (response.status === 404) return null;
  const data = await jsonResponse(response, 'Google Drive 备份文件夹读取失败');
  return data.mimeType === FOLDER_MIME && data.trashed !== true ? data : null;
}

async function createFolder(accessToken, name = '风险中心备份') {
  const response = await fetchWithTimeout(`${DRIVE_API}?fields=id,name,webViewLink`, {
    method: 'POST',
    headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ name, mimeType: FOLDER_MIME })
  });
  return jsonResponse(response, 'Google Drive 备份文件夹创建失败');
}

async function ensurePersonalFolder(accessToken, folderId, folderName = '风险中心备份') {
  const existing = await getFolder(accessToken, folderId);
  if (existing) return existing;
  return createFolder(accessToken, folderName);
}

async function uploadJsonWithToken({ accessToken, folderId, fileName, content }) {
  if (!/^[A-Za-z0-9_-]{5,200}$/.test(String(folderId || ''))) throw new Error('Google Drive 文件夹 ID 无效');
  const boundary = `risk_${crypto.randomBytes(12).toString('hex')}`;
  const metadata = JSON.stringify({ name: fileName, parents: [folderId], mimeType: 'application/json' });
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`),
    Buffer.from(content), Buffer.from(`\r\n--${boundary}--`)
  ]);
  const response = await fetchWithTimeout(`${DRIVE_UPLOAD}?uploadType=multipart&fields=id,name,webViewLink`, {
    method: 'POST',
    headers: { authorization: `Bearer ${accessToken}`, 'content-type': `multipart/related; boundary=${boundary}` },
    body
  }, 15_000);
  const data = await jsonResponse(response, 'Google Drive 上传失败');
  if (!data.id) throw new Error('Google Drive 上传成功但未返回文件 ID');
  return data;
}

async function deleteFile(accessToken, fileId) {
  const response = await fetchWithTimeout(`${DRIVE_API}/${encodeURIComponent(fileId)}`, {
    method: 'DELETE', headers: { authorization: `Bearer ${accessToken}` }
  });
  if (!response.ok && response.status !== 404) throw new Error(`测试文件清理失败（${response.status}）`);
}

async function serviceAccountAccessToken(credentials) {
  if (!credentials || credentials.type !== 'service_account'
    || credentials.token_uri !== TOKEN_URL || !credentials.client_email || !credentials.private_key) {
    throw new Error('Google Drive 服务账号凭证无效');
  }
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = base64url(JSON.stringify({
    iss: credentials.client_email, scope: DRIVE_SCOPE, aud: TOKEN_URL, iat: now, exp: now + 3600
  }));
  const unsigned = `${header}.${claim}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(unsigned), credentials.private_key).toString('base64url');
  const response = await fetchWithTimeout(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${signature}` })
  });
  const data = await jsonResponse(response, 'Google OAuth 服务账号授权失败');
  if (!data.access_token) throw new Error('Google OAuth 未返回服务账号访问令牌');
  return data.access_token;
}

async function uploadJson({ credentials, folderId, fileName, content }) {
  const accessToken = await serviceAccountAccessToken(credentials);
  return uploadJsonWithToken({ accessToken, folderId, fileName, content });
}

async function uploadPersonalJson({ clientId, clientSecret, refreshToken, folderId, fileName, content }) {
  const accessToken = await personalAccessToken({ clientId, clientSecret, refreshToken });
  return uploadJsonWithToken({ accessToken, folderId, fileName, content });
}

async function testConnection({ credentials, folderId }) {
  const accessToken = await serviceAccountAccessToken(credentials);
  const name = `risk-center-connection-test-${Date.now()}.json`;
  const file = await uploadJsonWithToken({ accessToken, folderId, fileName: name, content: JSON.stringify({ test: true }) });
  await deleteFile(accessToken, file.id);
  return { serviceAccountEmail: credentials.client_email };
}

async function testPersonalConnection({ clientId, clientSecret, refreshToken, folderId, connectedEmail }) {
  const accessToken = await personalAccessToken({ clientId, clientSecret, refreshToken });
  const folder = await getFolder(accessToken, folderId);
  if (!folder) throw new Error('个人网盘备份文件夹不存在或已失去访问权限');
  const name = `risk-center-connection-test-${Date.now()}.json`;
  const file = await uploadJsonWithToken({ accessToken, folderId, fileName: name, content: JSON.stringify({ test: true }) });
  await deleteFile(accessToken, file.id);
  return { connectedEmail, folderId, folderName: folder.name };
}

async function revokeToken(token) {
  if (!token) return false;
  const response = await fetchWithTimeout(REVOKE_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token })
  });
  return response.ok;
}

module.exports = {
  DRIVE_SCOPE,
  pkceChallenge,
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  personalAccessToken,
  getAccount,
  ensurePersonalFolder,
  uploadPersonalJson,
  testPersonalConnection,
  revokeToken,
  uploadJson,
  testConnection
};
