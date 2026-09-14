'use strict';

const { run, all, withTransaction } = require('../config/database');

async function initializeFrontendOriginTable() {
  await run(`CREATE TABLE IF NOT EXISTS frontend_origins (
    origin TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_frontend_origins_enabled_expiry
    ON frontend_origins(enabled, expires_at)`);
}

function listEnabledOrigins() {
  return all(`SELECT origin, expires_at
    FROM frontend_origins
    WHERE enabled = 1
      AND (expires_at IS NULL OR expires_at > datetime('now'))
    ORDER BY origin ASC`);
}

function listAllOrigins() {
  return all(`SELECT origin, enabled, expires_at, created_at, updated_at
    FROM frontend_origins
    ORDER BY origin ASC`);
}

async function replaceOrigins(items) {
  return withTransaction(async transaction => {
    await transaction.run('DELETE FROM frontend_origins');
    for (const item of items) {
      await transaction.run(`INSERT INTO frontend_origins(origin, enabled, expires_at)
        VALUES (?, ?, ?)`, [item.origin, item.enabled ? 1 : 0, item.expiresAt || null]);
    }
    return { count: items.length };
  }, { priority: 'interactive', label: 'replace frontend origins', durability: 'full' });
}

module.exports = {
  initializeFrontendOriginTable,
  listEnabledOrigins,
  listAllOrigins,
  replaceOrigins
};
