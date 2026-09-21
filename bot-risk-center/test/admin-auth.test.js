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
  assert.equal(AdminAuthService.sessionFromRequest(request).csrfToken, session.csrfToken);
  AdminAuthService.destroySession(request);
  assert.equal(AdminAuthService.sessionFromRequest(request), null);
});
