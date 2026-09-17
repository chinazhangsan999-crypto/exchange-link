'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

test('fresh database starts without sample categories or partners', async () => {
  const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'webring-blank-db-'));
  process.env.NODE_ENV = 'test';
  process.env.DB_PATH = path.join(tempDirectory, 'webring.db');
  process.env.INITIAL_ADMIN_PASSWORD = 'BlankDatabaseTest123';
  process.env.CONTROL_CENTER_ENABLED = '0';

  const SystemModel = require('../src/models/SystemModel');
  const { get, closeDatabase } = require('../src/config/database');

  try {
    await SystemModel.initializeDatabase();
    const partners = await get('SELECT COUNT(*) AS count FROM partners');
    const categories = await get('SELECT COUNT(*) AS count FROM categories');
    const admins = await get('SELECT COUNT(*) AS count FROM admins');

    assert.equal(Number(partners.count), 0);
    assert.equal(Number(categories.count), 0);
    assert.equal(Number(admins.count), 1);
  } finally {
    await closeDatabase();
    fs.rmSync(tempDirectory, { recursive: true, force: true });
  }
});
