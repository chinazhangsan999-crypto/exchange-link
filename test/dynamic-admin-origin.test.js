'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('production starts before admin domain is chosen and keeps admin routes closed', () => {
  process.env.NODE_ENV = 'production';
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';
  delete process.env.ADMIN_FRONTEND_ORIGIN;

  const originService = require('../src/services/AdminFrontendOriginService');
  const { requireAdminFrontendBoundary } = require('../src/middlewares/adminBoundary');
  originService.setStoredOrigin('');

  function invoke(path, trustedFrontendOrigin = '') {
    const result = { status: null, ended: false, next: false };
    const response = {
      status(value) { result.status = value; return this; },
      end() { result.ended = true; return this; }
    };
    requireAdminFrontendBoundary({ path, trustedFrontendOrigin }, response, () => { result.next = true; });
    return result;
  }

  assert.deepEqual(invoke('/admin'), { status: 404, ended: true, next: false });
  assert.deepEqual(invoke('/api/admin/login'), { status: 404, ended: true, next: false });
  assert.deepEqual(invoke('/setup'), { status: null, ended: false, next: true });

  originService.setStoredDomain('admin.example.com');
  assert.deepEqual(invoke('/admin', 'https://admin.example.com'), {
    status: null, ended: false, next: true
  });
  assert.deepEqual(invoke('/admin', 'https://other.example.com'), {
    status: 404, ended: true, next: false
  });
});
