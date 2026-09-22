'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const AnalysisService = require('../src/services/AnalysisService');
const GoogleDriveService = require('../src/services/GoogleDriveService');

const root = path.join(__dirname, '..');

test('脱敏分析证据剔除身份凭证与完整查询参数', () => {
  const evidence = AnalysisService.sanitizeEvidence({
    path: '/detail?id=88&sid=secret', userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/122.0.0.0 Safari/537.36',
    ip: '203.0.113.1', cookie: 'session=secret', authorization: 'Bearer secret', sid: 'secret', token: 'secret',
    concurrency: 8, method: 'GET'
  });
  assert.equal(evidence.path, '/detail');
  assert.equal(evidence.client, 'Windows 10/11 · Chrome 122');
  assert.equal(evidence.concurrency, 8);
  assert.equal(evidence.method, 'GET');
  assert.equal(evidence.ip, undefined);
  assert.equal(evidence.cookie, undefined);
  assert.equal(evidence.authorization, undefined);
  assert.equal(JSON.stringify(evidence).includes('secret'), false);
});

test('分析接口、短期令牌、个人 Drive OAuth 设置和横向筛选控件完整', () => {
  const routes = fs.readFileSync(path.join(root, 'src/routes/index.js'), 'utf8');
  const migration = fs.readFileSync(path.join(root, 'migrations/005_analysis_drive.sql'), 'utf8');
  const oauthMigration = fs.readFileSync(path.join(root, 'migrations/006_personal_drive_oauth.sql'), 'utf8');
  const html = fs.readFileSync(path.join(root, 'public/admin.html'), 'utf8');
  const css = fs.readFileSync(path.join(root, 'public/admin.css'), 'utf8');
  const adminJs = fs.readFileSync(path.join(root, 'public/admin.js'), 'utf8');
  const drive = fs.readFileSync(path.join(root, 'src/services/GoogleDriveService.js'), 'utf8');
  assert.match(routes, /\/v1\/analysis\/suspects/);
  assert.match(routes, /requireAnalysisScope\('suspects:list'\)/);
  assert.match(routes, /analysis\/google-drive\/backup/);
  assert.match(routes, /analysis\/google-drive\/connect/);
  assert.match(routes, /analysis\/google-drive\/oauth\/callback/);
  assert.match(migration, /CREATE TABLE IF NOT EXISTS analysis_tokens/);
  assert.match(migration, /max_uses INTEGER NOT NULL DEFAULT 20/);
  assert.match(html, /class="inline-filter"/);
  assert.match(html, /id="generate-analysis-token"/);
  assert.match(html, /id="drive-form"/);
  assert.match(html, /id="analysis-backup-details"/);
  assert.doesNotMatch(html, /data-tab="analysis"/);
  assert.match(html, /id="connect-drive"/);
  assert.match(html, /id="drive-oauth-callback"/);
  assert.match(adminJs, /copy-drive-oauth-callback/);
  assert.match(adminJs, /Google OAuth 回调地址已复制/);
  assert.match(html, /Google Drive 个人网盘备份/);
  assert.doesNotMatch(html, /服务账号 JSON/);
  assert.match(css, /\.inline-filter \{ display: inline-flex/);
  assert.match(drive, /https:\/\/www\.googleapis\.com\/auth\/drive\.file/);
  assert.doesNotMatch(drive, /drive\.readonly/);
  assert.match(oauthMigration, /oauth_refresh_token_ciphertext/);
  assert.match(oauthMigration, /CREATE TABLE IF NOT EXISTS google_drive_oauth_states/);
});

test('个人 Google Drive 授权使用离线访问、最小 Drive 权限和 PKCE', () => {
  const verifier = 'test-verifier-with-enough-entropy-for-pkce';
  const url = new URL(GoogleDriveService.buildAuthorizationUrl({
    clientId: '123-example.apps.googleusercontent.com',
    redirectUri: 'https://risk.example/admin/api/analysis/google-drive/oauth/callback',
    state: 'single-use-state',
    codeChallenge: GoogleDriveService.pkceChallenge(verifier)
  }));
  assert.equal(url.origin, 'https://accounts.google.com');
  assert.equal(url.searchParams.get('access_type'), 'offline');
  assert.equal(url.searchParams.get('prompt'), 'consent');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.match(url.searchParams.get('scope'), /openid/);
  assert.match(url.searchParams.get('scope'), /https:\/\/www\.googleapis\.com\/auth\/drive\.file/);
  assert.doesNotMatch(url.searchParams.get('scope'), /auth\/drive(?:\s|$)/);
});
