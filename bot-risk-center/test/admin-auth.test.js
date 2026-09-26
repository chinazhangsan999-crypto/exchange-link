'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const AdminAuthService = require('../src/services/AdminAuthService');

test.afterEach(() => AdminAuthService.resetForTests());

test('风险后台只接受正确账号密码并签发 HttpOnly 严格会话', async () => {
  assert.equal(await AdminAuthService.createSession('admin', 'wrong-password'), null);
  assert.equal(await AdminAuthService.createSession('wrong-user', 'admin123'), null);
  const session = await AdminAuthService.createSession('admin', 'admin123');
  assert.ok(session.sessionId.length >= 32);
  assert.ok(session.csrfToken.length >= 24);
  assert.deepEqual(AdminAuthService.cookieOptions(), {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: AdminAuthService.SESSION_TTL_MS,
    path: '/admin'
  });

  const request = { get(name) { return name === 'cookie' ? `${AdminAuthService.COOKIE_NAME}=${session.sessionId}` : ''; } };
  assert.equal((await AdminAuthService.sessionFromRequest(request)).csrfToken, session.csrfToken);
  await AdminAuthService.destroySession(request);
  assert.equal(await AdminAuthService.sessionFromRequest(request), null);
});

test('管理员可修改账号密码且新密码使用独立 scrypt 盐值', async () => {
  const hash = await AdminAuthService.passwordHash('new-secure-password');
  assert.match(hash, /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{128}$/);
  assert.notEqual(hash, await AdminAuthService.passwordHash('new-secure-password'));
});

test('管理员密码规则允许八位首次密码', async () => {
  const session = await AdminAuthService.createSession('admin', 'admin123');
  const changed = await AdminAuthService.changeCredentials(session, 'admin123', 'admin', 'admin123');
  assert.equal(changed.username, 'admin');
});
