'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

test('enabled mirrors can initialize a fresh database without a pre-existing category', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-mirror-sync-'));
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.NODE_ENV = 'test';

  const database = require('../src/config/database');
  const SystemModel = require('../src/models/SystemModel');
  const MirrorModel = require('../src/models/MirrorModel');

  try {
    await SystemModel.initializeDatabase();
    await MirrorModel.initializeMirrorsTable();
    await database.run(`INSERT INTO mirrors(speed_name, partner_name, url, status)
      VALUES (?, ?, ?, 1)`, ['测试节点', '测试节点', 'https://node.example.com']);

    const first = await MirrorModel.syncMirrorsToPartners();
    const second = await MirrorModel.syncMirrorsToPartners();
    const category = await database.get('SELECT name FROM categories');
    const partner = await database.get(`SELECT category, is_internal, is_exempt, is_approved
      FROM partners WHERE domain = ?`, ['node.example.com']);
    const categoryCount = await database.get('SELECT COUNT(*) AS count FROM categories');

    assert.deepEqual(first, { inserted: 1, updated: 0, deleted: 0 });
    assert.deepEqual(second, { inserted: 0, updated: 1, deleted: 0 });
    assert.equal(category.name, '备用节点');
    assert.equal(Number(categoryCount.count), 1);
    assert.deepEqual(partner, {
      category: '备用节点', is_internal: 1, is_exempt: 1, is_approved: 1
    });
  } finally {
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
