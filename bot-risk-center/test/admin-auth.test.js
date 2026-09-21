'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

process.env.BOT_RISK_ADMIN_TOKEN = 'test-admin-token-01234567890123456789';

const AdminAuthService = require('../src/services/AdminAuthService');

test.afterEach(() => AdminAuthService.resetForTests());

test('风险后台只接受正确令牌并签发 HttpOnly 严格会话', () => {
  assert.equal(AdminAuthService.createSession('wrong-token'), null);
  const session = AdminAuthService.createSession(process.env.BOT_RISK_ADMIN_TOKEN);
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
