'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { selectAdminToken } = require('../src/middlewares/auth');

function request({ path, method = 'GET', cookie = '', bearer = '' }) {
  return {
    path,
    method,
    headers: { cookie },
    get(name) {
      if (String(name).toLowerCase() === 'authorization') return bearer ? `Bearer ${bearer}` : '';
      return '';
    }
  };
}

test('统一登录交换优先验证新 Bearer，不被旧 Cookie 遮蔽', () => {
  const req = request({
    path: '/api/admin/session/exchange',
    method: 'POST',
    cookie: 'webring_admin=expired-cookie',
    bearer: 'fresh-control-center-token'
  });
  assert.equal(selectAdminToken(req), 'fresh-control-center-token');
});

test('普通后台请求仍优先使用 HttpOnly Cookie', () => {
  const req = request({
    path: '/api/admin/session',
    cookie: 'webring_admin=current-cookie',
    bearer: 'unexpected-bearer'
  });
  assert.equal(selectAdminToken(req), 'current-cookie');
});

test('统一登录交换没有 Bearer 时仍可回退现有 Cookie', () => {
  const req = request({
    path: '/api/admin/session/exchange',
    method: 'POST',
    cookie: 'webring_admin=current-cookie'
  });
  assert.equal(selectAdminToken(req), 'current-cookie');
});
