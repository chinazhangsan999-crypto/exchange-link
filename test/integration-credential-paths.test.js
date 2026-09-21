'use strict';

const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

test('production integration credentials default to the current user home', () => {
  process.env.NODE_ENV = 'production';
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';
  process.env.FRONTEND_PROXY_SECRET = 'test-frontend-proxy-secret-0123456789';
  delete process.env.CONTROL_CENTER_CREDENTIAL_FILE;
  delete process.env.IP_INTELLIGENCE_CREDENTIAL_FILE;
  delete process.env.BOT_RISK_CREDENTIAL_FILE;

  const CredentialStore = require('../src/services/IntegrationCredentialStore');

  assert.equal(
    CredentialStore.paths.controlCenter,
    path.join(os.homedir(), 'app-secrets', 'control-center-site.json')
  );
  assert.equal(
    CredentialStore.paths.ipIntelligence,
    path.join(os.homedir(), 'app-secrets', 'ip-intelligence.json')
  );
  assert.equal(
    CredentialStore.paths.botRisk,
    path.join(os.homedir(), 'app-secrets', 'bot-risk-center.json')
  );
});
