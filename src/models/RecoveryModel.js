'use strict';

const crypto = require('crypto');
const { run, get, all, withTransaction } = require('../config/database');

const SETTING_FIELDS = new Set([
  'enabled', 'recovery_email', 'recovery_publish_url', 'recovery_contact',
  'recovery_message', 'found_message', 'manifest_valid_days', 'max_domains',
  'probe_timeout_ms', 'probe_concurrency'
]);

async function initializeRecoveryTables() {
  await run(`CREATE TABLE IF NOT EXISTS recovery_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    project_id TEXT NOT NULL DEFAULT '',
    recovery_email TEXT NOT NULL DEFAULT '',
    recovery_publish_url TEXT NOT NULL DEFAULT '',
    recovery_contact TEXT NOT NULL DEFAULT '',
    recovery_message TEXT NOT NULL DEFAULT '请保存最新地址，谨防仿冒网站。',
    found_message TEXT NOT NULL DEFAULT '该地址已经过恢复清单签名和动态线路检测。',
    current_generation INTEGER NOT NULL DEFAULT 0,
    public_key_id TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL DEFAULT '',
    next_public_key_id TEXT NOT NULL DEFAULT '',
    next_public_key TEXT NOT NULL DEFAULT '',
    manifest_valid_days INTEGER NOT NULL DEFAULT 90,
    max_domains INTEGER NOT NULL DEFAULT 10,
    probe_timeout_ms INTEGER NOT NULL DEFAULT 3000,
    probe_concurrency INTEGER NOT NULL DEFAULT 3,
    component_version TEXT NOT NULL DEFAULT 'recovery-v1',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`INSERT OR IGNORE INTO recovery_settings(id, project_id)
    VALUES (1, ?)`, [`navigation-recovery-${crypto.randomBytes(6).toString('hex')}`]);

  await run(`CREATE TABLE IF NOT EXISTS recovery_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    priority INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 1,
    last_probe_status TEXT NOT NULL DEFAULT 'untested',
    last_probe_ms INTEGER DEFAULT NULL,
    last_probe_error TEXT NOT NULL DEFAULT '',
    last_probe_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_domains_status_priority ON recovery_domains(status, priority DESC, id ASC)');

  await run(`CREATE TABLE IF NOT EXISTS recovery_bootstrap_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    record_name TEXT NOT NULL UNIQUE,
    zone_name TEXT NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    last_publish_status TEXT NOT NULL DEFAULT 'unpublished',
    last_publish_error TEXT NOT NULL DEFAULT '',
    last_published_generation INTEGER NOT NULL DEFAULT 0,
    last_published_at DATETIME DEFAULT NULL,
    last_verified_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_bootstrap_order ON recovery_bootstrap_records(status, is_primary, sort_order, id)');

  await run(`CREATE TABLE IF NOT EXISTS recovery_releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    generation INTEGER NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    published_at DATETIME DEFAULT NULL,
    source_release_id INTEGER DEFAULT NULL,
    publish_error TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(source_release_id) REFERENCES recovery_releases(id) ON DELETE SET NULL
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_releases_status_generation ON recovery_releases(status, generation DESC)');

  await run(`CREATE TABLE IF NOT EXISTS recovery_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    success INTEGER NOT NULL DEFAULT 1,
    error_message TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_audit_time ON recovery_audit_logs(created_at DESC)');
}

async function getSettings() {
  return get('SELECT * FROM recovery_settings WHERE id = 1');
}

async function updateSettings(input = {}) {
  const entries = Object.entries(input).filter(([key]) => SETTING_FIELDS.has(key));
  if (!entries.length) return getSettings();
  const assignments = entries.map(([key]) => `${key} = ?`).join(', ');
  await run(`UPDATE recovery_settings SET ${assignments}, updated_at = CURRENT_TIMESTAMP WHERE id = 1`, entries.map(([, value]) => value));
  return getSettings();
}

async function saveKeyState(fields = {}) {
  const allowed = ['public_key_id', 'public_key', 'next_public_key_id', 'next_public_key'];
  const entries = Object.entries(fields).filter(([key]) => allowed.includes(key));
  if (!entries.length) return getSettings();
  await run(`UPDATE recovery_settings SET ${entries.map(([key]) => `${key} = ?`).join(', ')},
    updated_at = CURRENT_TIMESTAMP WHERE id = 1`, entries.map(([, value]) => value));
  return getSettings();
}

async function setCurrentGeneration(generation) {
  await run(`UPDATE recovery_settings SET current_generation = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`, [generation]);
}

async function listDomains({ enabledOnly = false } = {}) {
  return all(`SELECT * FROM recovery_domains ${enabledOnly ? 'WHERE status = 1' : ''}
    ORDER BY priority DESC, id ASC`);
}

async function getDomain(id) {
  return get('SELECT * FROM recovery_domains WHERE id = ?', [id]);
}

async function createDomain(input) {
  const result = await run(`INSERT INTO recovery_domains(title, url, priority, status)
    VALUES (?, ?, ?, ?)`, [input.title, input.url, input.priority, input.status]);
  return getDomain(result.id);
}

async function updateDomain(id, input) {
  await run(`UPDATE recovery_domains SET title = ?, url = ?, priority = ?, status = ?,
    updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [input.title, input.url, input.priority, input.status, id]);
  return getDomain(id);
}

async function deleteDomain(id) {
  return run('DELETE FROM recovery_domains WHERE id = ?', [id]);
}

async function saveProbeResult(id, result) {
  await run(`UPDATE recovery_domains SET last_probe_status = ?, last_probe_ms = ?,
    last_probe_error = ?, last_probe_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
  [result.healthy ? 'healthy' : 'failed', result.elapsedMs ?? null, result.error || '', id]);
  return getDomain(id);
}

async function listBootstrapRecords({ enabledOnly = false } = {}) {
  return all(`SELECT * FROM recovery_bootstrap_records ${enabledOnly ? 'WHERE status = 1' : ''}
    ORDER BY is_primary ASC, sort_order ASC, id ASC`);
}

async function getBootstrapRecord(id) {
  return get('SELECT * FROM recovery_bootstrap_records WHERE id = ?', [id]);
}

async function createBootstrapRecord(input) {
  const result = await run(`INSERT INTO recovery_bootstrap_records
    (label, record_name, zone_name, is_primary, status, sort_order) VALUES (?, ?, ?, ?, ?, ?)`,
  [input.label, input.recordName, input.zoneName, input.isPrimary, input.status, input.sortOrder]);
  return getBootstrapRecord(result.id);
}

async function updateBootstrapRecord(id, input) {
  await run(`UPDATE recovery_bootstrap_records SET label = ?, record_name = ?, zone_name = ?,
    is_primary = ?, status = ?, sort_order = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
  [input.label, input.recordName, input.zoneName, input.isPrimary, input.status, input.sortOrder, id]);
  return getBootstrapRecord(id);
}

async function deleteBootstrapRecord(id) {
  return run('DELETE FROM recovery_bootstrap_records WHERE id = ?', [id]);
}

async function saveBootstrapPublishResult(id, result) {
  await run(`UPDATE recovery_bootstrap_records SET last_publish_status = ?, last_publish_error = ?,
    last_published_generation = CASE WHEN ? > 0 THEN ? ELSE last_published_generation END,
    last_published_at = CASE WHEN ? > 0 THEN CURRENT_TIMESTAMP ELSE last_published_at END,
    last_verified_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE last_verified_at END,
    updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [
    result.status, result.error || '', result.generation || 0, result.generation || 0,
    result.generation || 0, result.verified ? 1 : 0, id
  ]);
}

async function nextGeneration() {
  const row = await get(`SELECT MAX(generation) AS generation FROM recovery_releases`);
  return Math.max(Number(row?.generation || 0), Number((await getSettings())?.current_generation || 0)) + 1;
}

async function createRelease(input) {
  const result = await run(`INSERT INTO recovery_releases
    (generation, payload_json, payload_hash, signature, key_id, status, issued_at, expires_at, source_release_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
    input.generation, input.payloadJson, input.payloadHash, input.signature, input.keyId,
    input.status || 'draft', input.issuedAt, input.expiresAt, input.sourceReleaseId || null
  ]);
  return getRelease(result.id);
}

async function getRelease(id) {
  return get('SELECT * FROM recovery_releases WHERE id = ?', [id]);
}

async function getReleaseByGeneration(generation) {
  return get('SELECT * FROM recovery_releases WHERE generation = ?', [generation]);
}

async function listReleases(limit = 50) {
  return all('SELECT * FROM recovery_releases ORDER BY generation DESC LIMIT ?', [Math.max(1, Math.min(200, Number(limit) || 50))]);
}

async function getLatestPublishedRelease() {
  return get(`SELECT * FROM recovery_releases WHERE status = 'published' ORDER BY generation DESC LIMIT 1`);
}

async function markRelease(id, status, fields = {}) {
  const published = status === 'published' ? ', published_at = CURRENT_TIMESTAMP' : '';
  await run(`UPDATE recovery_releases SET status = ?, publish_error = ?${published} WHERE id = ?`,
    [status, fields.error || '', id]);
  return getRelease(id);
}

async function publishReleaseAtomically(id, generation) {
  return withTransaction(async ({ run: txRun }) => {
    await txRun(`UPDATE recovery_releases SET status = 'superseded'
      WHERE status = 'published' AND id <> ?`, [id]);
    await txRun(`UPDATE recovery_releases SET status = 'published', publish_error = '',
      published_at = CURRENT_TIMESTAMP WHERE id = ?`, [id]);
    await txRun(`UPDATE recovery_settings SET current_generation = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`, [generation]);
  }, { durability: 'full', label: 'publish recovery release' });
}

async function addAudit(action, detail = {}, success = true, errorMessage = '') {
  await run(`INSERT INTO recovery_audit_logs(action, detail_json, success, error_message)
    VALUES (?, ?, ?, ?)`, [action, JSON.stringify(detail), success ? 1 : 0, String(errorMessage || '')]);
}

async function listAudit(limit = 100) {
  return all('SELECT * FROM recovery_audit_logs ORDER BY id DESC LIMIT ?', [Math.max(1, Math.min(500, Number(limit) || 100))]);
}

module.exports = {
  initializeRecoveryTables,
  getSettings,
  updateSettings,
  saveKeyState,
  setCurrentGeneration,
  listDomains,
  getDomain,
  createDomain,
  updateDomain,
  deleteDomain,
  saveProbeResult,
  listBootstrapRecords,
  getBootstrapRecord,
  createBootstrapRecord,
  updateBootstrapRecord,
  deleteBootstrapRecord,
  saveBootstrapPublishResult,
  nextGeneration,
  createRelease,
  getRelease,
  getReleaseByGeneration,
  listReleases,
  getLatestPublishedRelease,
  markRelease,
  publishReleaseAtomically,
  addAudit,
  listAudit
};
