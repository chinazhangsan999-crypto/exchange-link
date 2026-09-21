'use strict';

const { run, get, all, withTransaction } = require('../config/database');

async function ensureColumn(table, name, definition) {
  const columns = await all(`PRAGMA table_info(${table})`);
  if (!columns.some(column => column.name === name)) await run(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
}

async function initializeCloudflareFrontendTables() {
  await run(`CREATE TABLE IF NOT EXISTS cloudflare_frontend_accounts (
    id TEXT PRIMARY KEY, label TEXT NOT NULL, account_id TEXT NOT NULL UNIQUE,
    worker_prefix TEXT NOT NULL, next_worker_number INTEGER NOT NULL DEFAULT 1 CHECK(next_worker_number > 0),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await ensureColumn('cloudflare_frontend_accounts', 'token_fingerprint', 'TEXT');
  await ensureColumn('cloudflare_frontend_accounts', 'token_status', "TEXT NOT NULL DEFAULT 'unverified'");
  await ensureColumn('cloudflare_frontend_accounts', 'last_verified_at', 'DATETIME');
  await ensureColumn('cloudflare_frontend_accounts', 'last_error', 'TEXT');
  await ensureColumn('cloudflare_frontend_accounts', 'allocation_enabled', 'INTEGER NOT NULL DEFAULT 1');
  await ensureColumn('cloudflare_frontend_accounts', 'active_zones_json', 'TEXT');
  await ensureColumn('cloudflare_frontend_accounts', 'is_primary', 'INTEGER NOT NULL DEFAULT 0');
  await ensureColumn('cloudflare_frontend_accounts', 'retired_at', 'DATETIME');

  await run(`CREATE TABLE IF NOT EXISTS cloudflare_frontend_workers (
    id INTEGER PRIMARY KEY AUTOINCREMENT, account_profile_id TEXT NOT NULL,
    worker_name TEXT NOT NULL UNIQUE, hostname TEXT UNIQUE, zone_name TEXT,
    state TEXT NOT NULL, error_message TEXT, health_json TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(account_profile_id) REFERENCES cloudflare_frontend_accounts(id) ON DELETE CASCADE
  )`);
  await ensureColumn('cloudflare_frontend_workers', 'cloudflare_domain_id', 'TEXT');
  await ensureColumn('cloudflare_frontend_workers', 'is_primary', 'INTEGER NOT NULL DEFAULT 0');
  await ensureColumn('cloudflare_frontend_workers', 'migration_state', "TEXT NOT NULL DEFAULT 'none'");
  await ensureColumn('cloudflare_frontend_workers', 'previous_worker_id', 'INTEGER');
  await ensureColumn('cloudflare_frontend_workers', 'remote_cleanup_policy', "TEXT NOT NULL DEFAULT 'keep'");
  await ensureColumn('cloudflare_frontend_workers', 'last_health_at', 'DATETIME');
  await ensureColumn('cloudflare_frontend_workers', 'last_deployed_at', 'DATETIME');
  await ensureColumn('cloudflare_frontend_workers', 'retired_at', 'DATETIME');
  await ensureColumn('cloudflare_frontend_workers', 'retained_hostname', 'TEXT');
  await ensureColumn('cloudflare_frontend_workers', 'recovery_profile_id', 'INTEGER NOT NULL DEFAULT 1');

  await run(`CREATE TABLE IF NOT EXISTS cloudflare_central_state (
    id INTEGER PRIMARY KEY CHECK(id = 1), account_id TEXT, api_worker_name TEXT, api_domain TEXT,
    admin_worker_name TEXT, admin_domain TEXT, origin_url TEXT, token_fingerprint TEXT,
    token_status TEXT NOT NULL DEFAULT 'unverified', api_health_json TEXT, admin_health_json TEXT,
    last_error TEXT, last_verified_at DATETIME, last_deployed_at DATETIME,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS cloudflare_frontend_migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT NOT NULL,
    source_account_profile_id TEXT, target_account_profile_id TEXT NOT NULL,
    source_worker_id INTEGER, target_worker_id INTEGER, migration_type TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'prepared', keep_old_resources INTEGER NOT NULL DEFAULT 1,
    error_message TEXT, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, completed_at DATETIME
  )`);
  await run(`CREATE TABLE IF NOT EXISTS cloudflare_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, admin_username TEXT, action TEXT NOT NULL,
    target_type TEXT NOT NULL, target_id TEXT, success INTEGER NOT NULL,
    detail_json TEXT, client_ip TEXT, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_cf_frontend_workers_account_state ON cloudflare_frontend_workers(account_profile_id, state, created_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_cf_frontend_workers_hostname ON cloudflare_frontend_workers(hostname)');
  await run('CREATE INDEX IF NOT EXISTS idx_cf_migrations_hostname_state ON cloudflare_frontend_migrations(hostname, state, created_at DESC)');
}

const accountColumns = `id, label, account_id, worker_prefix, next_worker_number, enabled,
  token_fingerprint, token_status, last_verified_at, last_error, allocation_enabled,
  active_zones_json, is_primary, retired_at, created_at, updated_at`;

function listAccounts() { return all(`SELECT ${accountColumns} FROM cloudflare_frontend_accounts ORDER BY is_primary DESC, created_at ASC`); }
function getAccount(id) { return get(`SELECT ${accountColumns} FROM cloudflare_frontend_accounts WHERE id = ?`, [id]); }
function getAccountByAccountId(accountId) { return get(`SELECT ${accountColumns} FROM cloudflare_frontend_accounts WHERE account_id = ?`, [accountId]); }

async function upsertAccount(account) {
  return withTransaction(async transaction => {
    const existing = await transaction.get('SELECT * FROM cloudflare_frontend_accounts WHERE id = ?', [account.id]);
    if (existing && existing.account_id !== account.accountId) {
      const worker = await transaction.get('SELECT id FROM cloudflare_frontend_workers WHERE account_profile_id = ? LIMIT 1', [account.id]);
      if (worker) throw new Error('该账号已创建 Worker，Account ID 已锁定；更换账号请新增配置');
    }
    await transaction.run(`INSERT INTO cloudflare_frontend_accounts(
        id, label, account_id, worker_prefix, enabled, token_fingerprint, token_status,
        last_verified_at, last_error, allocation_enabled, active_zones_json, is_primary)
      VALUES (?, ?, ?, ?, 1, ?, ?, CURRENT_TIMESTAMP, NULL, 1, ?, ?)
      ON CONFLICT(id) DO UPDATE SET label = excluded.label, account_id = excluded.account_id,
        worker_prefix = excluded.worker_prefix, token_fingerprint = excluded.token_fingerprint,
        token_status = excluded.token_status, last_verified_at = CURRENT_TIMESTAMP, last_error = NULL,
        active_zones_json = excluded.active_zones_json, updated_at = CURRENT_TIMESTAMP`, [
      account.id, account.label, account.accountId, account.workerPrefix,
      account.tokenFingerprint || null, account.tokenStatus || 'valid',
      JSON.stringify(account.activeZones || []), account.isPrimary ? 1 : 0
    ]);
    return { created: !existing, account: await transaction.get('SELECT * FROM cloudflare_frontend_accounts WHERE id = ?', [account.id]) };
  }, { priority: 'interactive', label: 'save Cloudflare frontend account', durability: 'full' });
}

function updateAccountVerification(id, values) {
  return run(`UPDATE cloudflare_frontend_accounts SET token_status = ?,
    token_fingerprint = COALESCE(?, token_fingerprint), active_zones_json = COALESCE(?, active_zones_json),
    last_error = ?, last_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [
    values.status, values.tokenFingerprint || null,
    values.activeZones ? JSON.stringify(values.activeZones) : null, values.error || null, id
  ]);
}

function setAccountAllocation(id, enabled) {
  return run(`UPDATE cloudflare_frontend_accounts SET allocation_enabled = ?, enabled = ?,
    retired_at = CASE WHEN ? = 1 THEN NULL ELSE retired_at END, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
  [enabled ? 1 : 0, enabled ? 1 : 0, enabled ? 1 : 0, id]);
}

async function reserveWorker(profileId, hostname = null, zoneName = null, options = {}) {
  return withTransaction(async transaction => {
    const account = await transaction.get(`SELECT id, worker_prefix, next_worker_number, enabled, allocation_enabled
      FROM cloudflare_frontend_accounts WHERE id = ?`, [profileId]);
    if (!account || Number(account.enabled) !== 1 || Number(account.allocation_enabled) !== 1) {
      throw new Error('公共前台 Cloudflare 账号不存在、已停用或已停止分配');
    }
    if (hostname && options.allowExisting !== true) {
      const existing = await transaction.get('SELECT id, worker_name, state FROM cloudflare_frontend_workers WHERE hostname = ?', [hostname]);
      if (existing?.state === 'failed') await transaction.run('DELETE FROM cloudflare_frontend_workers WHERE id = ?', [existing.id]);
      else if (existing) throw new Error(`该前台域名已记录在 Worker ${existing.worker_name}（${existing.state}）`);
    }
    const number = Number(account.next_worker_number);
    const workerName = `${account.worker_prefix}-${String(number).padStart(3, '0')}`;
    await transaction.run('UPDATE cloudflare_frontend_accounts SET next_worker_number = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [number + 1, profileId]);
    const inserted = await transaction.run(`INSERT INTO cloudflare_frontend_workers(
      account_profile_id, worker_name, hostname, zone_name, state, previous_worker_id, migration_state, recovery_profile_id)
      VALUES (?, ?, ?, ?, 'creating', ?, ?, ?)`, [profileId, workerName, hostname, zoneName,
      options.previousWorkerId || null, options.migrationState || 'none', Number(options.recoveryProfileId) || 1]);
    return { id: inserted.id, workerName, hostname, zoneName };
  }, { priority: 'interactive', label: 'reserve Cloudflare frontend worker', durability: 'full' });
}

async function updateWorker(workerId, values = {}) {
  const current = await getWorker(workerId);
  if (!current) return { changes: 0 };
  return run(`UPDATE cloudflare_frontend_workers SET state = ?, error_message = ?, health_json = ?,
    cloudflare_domain_id = ?, migration_state = ?,
    last_health_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_health_at END,
    last_deployed_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_deployed_at END,
    retired_at = CASE WHEN ? = 'retired' THEN CURRENT_TIMESTAMP ELSE retired_at END,
    updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [
    values.state ?? current.state,
    values.errorMessage === undefined ? current.error_message : values.errorMessage,
    values.health === undefined ? current.health_json : JSON.stringify(values.health),
    values.domainId === undefined ? current.cloudflare_domain_id : values.domainId,
    values.migrationState ?? current.migration_state,
    values.health === undefined ? 0 : 1, values.deployed ? 1 : 0,
    values.state ?? current.state, workerId
  ]);
}

function getWorker(id) {
  return get(`SELECT w.*, a.label AS account_label, a.account_id FROM cloudflare_frontend_workers w
    JOIN cloudflare_frontend_accounts a ON a.id = w.account_profile_id WHERE w.id = ?`, [id]);
}
function getWorkerByHostname(hostname) {
  return get(`SELECT w.*, a.label AS account_label, a.account_id FROM cloudflare_frontend_workers w
    JOIN cloudflare_frontend_accounts a ON a.id = w.account_profile_id WHERE w.hostname = ?`, [hostname]);
}
function listWorkers() {
  return all(`SELECT w.*, a.label AS account_label, a.account_id FROM cloudflare_frontend_workers w
    JOIN cloudflare_frontend_accounts a ON a.id = w.account_profile_id
    ORDER BY w.is_primary DESC, w.created_at DESC, w.id DESC`);
}

function getCentralState() { return get('SELECT * FROM cloudflare_central_state WHERE id = 1'); }
function saveCentralState(values = {}) {
  return run(`INSERT INTO cloudflare_central_state(
      id, account_id, api_worker_name, api_domain, admin_worker_name, admin_domain, origin_url,
      token_fingerprint, token_status, api_health_json, admin_health_json, last_error,
      last_verified_at, last_deployed_at)
    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END,
      CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END)
    ON CONFLICT(id) DO UPDATE SET account_id = excluded.account_id,
      api_worker_name = excluded.api_worker_name, api_domain = excluded.api_domain,
      admin_worker_name = excluded.admin_worker_name, admin_domain = excluded.admin_domain,
      origin_url = excluded.origin_url, token_fingerprint = COALESCE(excluded.token_fingerprint, token_fingerprint),
      token_status = excluded.token_status, api_health_json = COALESCE(excluded.api_health_json, api_health_json),
      admin_health_json = COALESCE(excluded.admin_health_json, admin_health_json), last_error = excluded.last_error,
      last_verified_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_verified_at END,
      last_deployed_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_deployed_at END,
      updated_at = CURRENT_TIMESTAMP`, [
    values.accountId || null, values.apiWorkerName || null, values.apiDomain || null,
    values.adminWorkerName || null, values.adminDomain || null, values.originUrl || null,
    values.tokenFingerprint || null, values.tokenStatus || 'unverified',
    values.apiHealth ? JSON.stringify(values.apiHealth) : null,
    values.adminHealth ? JSON.stringify(values.adminHealth) : null,
    values.error || null, values.verified ? 1 : 0, values.deployed ? 1 : 0,
    values.verified ? 1 : 0, values.deployed ? 1 : 0
  ]);
}

function createMigration(values) {
  return run(`INSERT INTO cloudflare_frontend_migrations(hostname, source_account_profile_id,
    target_account_profile_id, source_worker_id, migration_type, state, keep_old_resources)
    VALUES (?, ?, ?, ?, ?, 'prepared', ?)`, [values.hostname, values.sourceAccountProfileId || null,
    values.targetAccountProfileId, values.sourceWorkerId || null, values.migrationType,
    values.keepOldResources === false ? 0 : 1]);
}
function getMigration(id) { return get('SELECT * FROM cloudflare_frontend_migrations WHERE id = ?', [id]); }
function listMigrations() { return all('SELECT * FROM cloudflare_frontend_migrations ORDER BY created_at DESC, id DESC LIMIT 100'); }
function updateMigration(id, state, values = {}) {
  return run(`UPDATE cloudflare_frontend_migrations SET state = ?, target_worker_id = COALESCE(?, target_worker_id),
    error_message = ?, completed_at = CASE WHEN ? IN ('completed', 'rolled_back') THEN CURRENT_TIMESTAMP ELSE completed_at END
    WHERE id = ?`, [state, values.targetWorkerId || null, values.error || null, state, id]);
}

function logAudit(entry) {
  return run(`INSERT INTO cloudflare_audit_logs(admin_username, action, target_type, target_id, success, detail_json, client_ip)
    VALUES (?, ?, ?, ?, ?, ?, ?)`, [entry.adminUsername || null, entry.action, entry.targetType,
    entry.targetId == null ? null : String(entry.targetId), entry.success ? 1 : 0,
    entry.detail ? JSON.stringify(entry.detail) : null, entry.clientIp || null]);
}

function promoteMigratedWorker(sourceWorkerId, targetWorkerId, hostname, domainId) {
  return withTransaction(async transaction => {
    await transaction.run(`UPDATE cloudflare_frontend_workers SET retained_hostname = hostname,
      hostname = NULL, migration_state = 'retained', remote_cleanup_policy = 'keep', updated_at = CURRENT_TIMESTAMP
      WHERE id = ?`, [sourceWorkerId]);
    await transaction.run(`UPDATE cloudflare_frontend_workers SET hostname = ?, cloudflare_domain_id = ?,
      state = 'ready', migration_state = 'cutover', last_deployed_at = CURRENT_TIMESTAMP,
      updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [hostname, domainId || null, targetWorkerId]);
  }, { priority: 'interactive', label: 'promote migrated Cloudflare frontend', durability: 'full' });
}

module.exports = {
  initializeCloudflareFrontendTables,
  listAccounts, getAccount, getAccountByAccountId, upsertAccount, updateAccountVerification, setAccountAllocation,
  reserveWorker, updateWorker, getWorker, getWorkerByHostname, listWorkers,
  getCentralState, saveCentralState, createMigration, getMigration, listMigrations, updateMigration, promoteMigratedWorker, logAudit
};
