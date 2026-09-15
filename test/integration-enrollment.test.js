'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const bcrypt = require('bcryptjs');

test('未接管使用引导密码，接管后永久关闭本地登录并使旧会话失效', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-enrollment-'));
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.NODE_ENV = 'test';
  delete process.env.CONTROL_CENTER_ENABLED;
  delete process.env.INITIAL_ADMIN_PASSWORD;

  const database = require('../src/config/database');
  const SystemModel = require('../src/models/SystemModel');
  const IntegrationState = require('../src/services/IntegrationStateService');
  try {
    await SystemModel.initializeDatabase();
    await IntegrationState.initialize();
    const before = await SystemModel.getAdminByUsername('admin', 'password');
    assert.equal(await bcrypt.compare('admin123', before.password_hash), true);
    assert.equal(IntegrationState.isLocalPasswordLoginAllowed(), true);

    const replacementHash = await bcrypt.hash('not-a-login-password', 12);
    await IntegrationState.markEnrolled(replacementHash);
    const after = await SystemModel.getAdminByUsername('admin', 'password');
    assert.equal(IntegrationState.isControlCenterEnrolled(), true);
    assert.equal(IntegrationState.isLocalPasswordLoginAllowed(), false);
    assert.equal(Number(after.session_version), Number(before.session_version) + 1);
    assert.equal(await bcrypt.compare('admin123', after.password_hash), false);
  } finally {
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
