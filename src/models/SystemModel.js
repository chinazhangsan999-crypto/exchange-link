const bcrypt = require('bcryptjs');
const { run, get, all, withTransaction, writeGet } = require('../config/database');
const { INITIAL_ADMIN_PASSWORD, CONTROL_CENTER_ENABLED } = require('../config/env');

const CONFIG_DEFAULTS = {
  site_name: '星环导航',
  site_logo_url: '',
  site_url: 'http://localhost:3001',
  admin_contact: '请在后台系统设置中填写站长联系方式。',
  auto_approve_threshold: '10',
  publish_url: '',
  contact_email: '',
  contact_info: '请在后台系统设置中填写站长联系方式。',
  publish_modal_enabled: '1',
  webhook_url: '',
  bark_enabled: '0',
  bark_server_url: 'https://api.day.app',
  bark_device_key: '',
  bark_group: '星环导航告警',
  lost_prevention_email: '',
  umami_enabled: '0',
  umami_script_url: 'https://cloud.umami.is/script.js',
  umami_website_id: '',
  cf_analytics_enabled: '0',
  cf_beacon_token: '',
  generic_analytics_enabled: '0',
  generic_analytics_code: '',
  min_interaction_rate: '0.02',
  min_attributed_interaction_rate: '0.005',
  max_hourly_burst_ratio: '0.6',
  empty_referer_threshold: '0.5',
  pv_uv_ratio_threshold: '100.0',
  // 首次启用风险 Webhook 时只建立现有风险基线，避免把历史存量一次性刷屏。
  risk_alert_webhook_baselined: '0',
  csv_url_partners: '',
  csv_url_ads: '',
  csv_url_mirrors: ''
};

const RISK_CONTROL_CONFIG_KEYS = [
  'min_interaction_rate',
  'min_attributed_interaction_rate',
  'max_hourly_burst_ratio',
  'empty_referer_threshold',
  'pv_uv_ratio_threshold'
];

async function configValue(key) {
  const row = await get('SELECT value FROM site_configs WHERE key = ?', [key]);
  return row?.value ?? CONFIG_DEFAULTS[key] ?? '';
}

async function getConfigValues(keys) {
  const result = {};
  for (const key of keys) result[key] = await configValue(key);
  return result;
}

async function getAllConfig() {
  return getConfigValues(Object.keys(CONFIG_DEFAULTS));
}

/** 返回可供风控服务实时使用的数值型阈值，避免各调用方重复解析字符串。 */
async function getRiskControlConfig() {
  const rows = await all(
    `SELECT key, value FROM site_configs WHERE key IN (${RISK_CONTROL_CONFIG_KEYS.map(() => '?').join(', ')})`,
    RISK_CONTROL_CONFIG_KEYS
  );
  const storedValues = new Map(rows.map(row => [row.key, row.value]));
  return Object.fromEntries(RISK_CONTROL_CONFIG_KEYS.map(key => {
    const configured = Number(storedValues.get(key));
    const fallback = Number(CONFIG_DEFAULTS[key]);
    return [key, Number.isFinite(configured) ? configured : fallback];
  }));
}

async function upsertConfig(key, value) {
  return withTransaction(
    ({ run: txRun }) => txRun(`INSERT INTO site_configs(key, value, updated_at)
      VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`, [key, value]),
    { priority: 'interactive', label: 'save system configuration', durability: 'full' }
  );
}

async function upsertConfigs(entries) {
  return withTransaction(async ({ run: txRun }) => {
    const results = [];
    for (const [key, value] of entries) {
      results.push(await txRun(`INSERT INTO site_configs(key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`, [key, value]));
    }
    return results;
  }, { priority: 'interactive', label: 'save system configuration', durability: 'full' });
}

async function getAdminByUsername(username, fields = 'full') {
  if (fields === 'password') return get('SELECT id, username, password_hash, session_version FROM admins WHERE username = ?', [username]);
  return get('SELECT * FROM admins WHERE username = ?', [username]);
}

async function getAdminSessionById(id) {
  return get('SELECT id, username, session_version FROM admins WHERE id = ?', [id]);
}

async function updateAdminPassword(id, passwordHash) {
  return withTransaction(
    ({ run: txRun }) => txRun('UPDATE admins SET password_hash = ?, session_version = session_version + 1 WHERE id = ?', [passwordHash, id]),
    { priority: 'interactive', label: 'change admin password', durability: 'full' }
  );
}

const INTEGRATION_STATE_DEFAULTS = {
  control_center_enrolled: '0',
  local_password_login_enabled: '1',
  bootstrap_password_active: '1'
};

async function getIntegrationState() {
  return getConfigValues(Object.keys(INTEGRATION_STATE_DEFAULTS));
}

async function completeControlCenterEnrollment(passwordHash) {
  return withTransaction(async ({ run: txRun }) => {
    const entries = {
      control_center_enrolled: '1',
      local_password_login_enabled: '0',
      bootstrap_password_active: '0'
    };
    for (const [key, value] of Object.entries(entries)) {
      await txRun(`INSERT INTO site_configs(key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`, [key, value]);
    }
    await txRun("UPDATE admins SET password_hash = ?, session_version = session_version + 1 WHERE username = 'admin'", [passwordHash]);
  }, { priority: 'interactive', label: 'complete control center enrollment', durability: 'full' });
}

async function listCategories() {
  return all('SELECT id, name, sort_order FROM categories ORDER BY sort_order, id');
}

async function listAdminCategories() {
  return all('SELECT * FROM categories ORDER BY sort_order, id');
}

async function categoryExists(name) {
  return get('SELECT id FROM categories WHERE name = ?', [name]);
}

async function createCategory(name) {
  const max = await get('SELECT COALESCE(MAX(sort_order), -1) AS n FROM categories');
  return run('INSERT INTO categories(name, sort_order) VALUES (?, ?)', [name, Number(max?.n || 0) + 1]);
}

async function saveCategoryOrder(items) {
  return withTransaction(async ({ run: txRun }) => {
    const results = [];
    for (let index = 0; index < items.length; index += 1) {
      results.push(await txRun(
        'UPDATE categories SET name = ?, sort_order = ? WHERE id = ?',
        [String(items[index].name).trim(), index, Number(items[index].id)]
      ));
    }
    return results;
  }, { priority: 'interactive', label: 'save category order', durability: 'full' });
}

async function deleteCategory(id) {
  const used = await get('SELECT id FROM partners WHERE category = (SELECT name FROM categories WHERE id = ?) LIMIT 1', [id]);
  if (used) return { used: true, changes: 0 };
  const result = await run('DELETE FROM categories WHERE id = ?', [id]);
  return { used: false, changes: result.changes };
}

async function runDatabaseMaintenance() {
  const checkpoint = await writeGet('PRAGMA wal_checkpoint(TRUNCATE)', [], { priority: 'maintenance', label: 'sqlite wal checkpoint' });
  await run('PRAGMA optimize', [], { priority: 'maintenance', label: 'sqlite optimize' });
  return { checkpoint };
}

async function initializeDatabase() {
  await run('PRAGMA foreign_keys = ON');
  await run('PRAGMA journal_mode = WAL');
  await run('PRAGMA synchronous = NORMAL');
  await run(`CREATE TABLE IF NOT EXISTS partners (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, domain TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL, category TEXT NOT NULL, description TEXT DEFAULT '', contact TEXT DEFAULT '', priority INTEGER DEFAULT 0,
    is_internal INTEGER DEFAULT 0, is_whitelisted INTEGER DEFAULT 0, is_exempt INTEGER DEFAULT 0,
    is_approved INTEGER DEFAULT 0,
    backlink_status TEXT DEFAULT 'pending', backlink_url TEXT DEFAULT NULL, last_checked_at DATETIME DEFAULT NULL, failed_check_count INTEGER DEFAULT 0, lost_count INTEGER DEFAULT 0,
    ping_exempt INTEGER DEFAULT 0, ping_failed_count INTEGER DEFAULT 0, ping_status TEXT DEFAULT 'ok', last_ping_at DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS inbound_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, link_id INTEGER NOT NULL, client_ip TEXT NOT NULL,
    user_agent TEXT DEFAULT '', referer TEXT DEFAULT NULL, visit_id TEXT DEFAULT NULL,
    source_token_id INTEGER DEFAULT NULL, sid_partner_id INTEGER DEFAULT NULL,
    domain_partner_id INTEGER DEFAULT NULL, attribution_method TEXT DEFAULT 'domain_only',
    observed_domain TEXT DEFAULT '', visitor_hash TEXT DEFAULT '', client_fingerprint TEXT DEFAULT '',
    screen_resolution TEXT DEFAULT '', client_language TEXT DEFAULT '', client_platform TEXT DEFAULT '',
    attempt_id TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(link_id) REFERENCES partners(id) ON DELETE CASCADE
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_time_link ON inbound_logs(created_at, link_id, client_ip)');
  const inboundDedupeIndex = await get("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_inbound_link_ip_time'");
  if (!inboundDedupeIndex?.sql || !/created_at\s+DESC/i.test(inboundDedupeIndex.sql)) {
    await run('DROP INDEX IF EXISTS idx_inbound_link_ip_time');
  }
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_link_ip_time ON inbound_logs(link_id, client_ip, created_at DESC)');
  const inboundColumns = await all('PRAGMA table_info(inbound_logs)');
  if (!inboundColumns.some(column => column.name === 'referer')) {
    await run('ALTER TABLE inbound_logs ADD COLUMN referer TEXT DEFAULT NULL');
  }
  if (!inboundColumns.some(column => column.name === 'visit_id')) {
    await run('ALTER TABLE inbound_logs ADD COLUMN visit_id TEXT DEFAULT NULL');
  }
  const inboundAttributionMigrations = [
    ['source_token_id', 'ALTER TABLE inbound_logs ADD COLUMN source_token_id INTEGER DEFAULT NULL'],
    ['sid_partner_id', 'ALTER TABLE inbound_logs ADD COLUMN sid_partner_id INTEGER DEFAULT NULL'],
    ['domain_partner_id', 'ALTER TABLE inbound_logs ADD COLUMN domain_partner_id INTEGER DEFAULT NULL'],
    ['attribution_method', "ALTER TABLE inbound_logs ADD COLUMN attribution_method TEXT DEFAULT 'domain_only'"],
    ['observed_domain', "ALTER TABLE inbound_logs ADD COLUMN observed_domain TEXT DEFAULT ''"],
    ['visitor_hash', "ALTER TABLE inbound_logs ADD COLUMN visitor_hash TEXT DEFAULT ''"],
    ['client_fingerprint', "ALTER TABLE inbound_logs ADD COLUMN client_fingerprint TEXT DEFAULT ''"],
    ['screen_resolution', "ALTER TABLE inbound_logs ADD COLUMN screen_resolution TEXT DEFAULT ''"],
    ['client_language', "ALTER TABLE inbound_logs ADD COLUMN client_language TEXT DEFAULT ''"],
    ['client_platform', "ALTER TABLE inbound_logs ADD COLUMN client_platform TEXT DEFAULT ''"],
    ['attempt_id', "ALTER TABLE inbound_logs ADD COLUMN attempt_id TEXT DEFAULT ''"]
  ];
  for (const [column, sql] of inboundAttributionMigrations) {
    if (!inboundColumns.some(item => item.name === column)) await run(sql);
  }
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_visit_time ON inbound_logs(visit_id, created_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_source_token_time ON inbound_logs(source_token_id, created_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_attribution_time ON inbound_logs(attribution_method, created_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_visitor_time ON inbound_logs(link_id, visitor_hash, created_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_fingerprint_time ON inbound_logs(link_id, client_fingerprint, created_at DESC)');
  await run(`CREATE TABLE IF NOT EXISTS inbound_rejection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip TEXT NOT NULL,
    visitor_hash TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    referer TEXT DEFAULT '',
    observed_domain TEXT DEFAULT '',
    partner_id INTEGER DEFAULT NULL,
    source_token_id INTEGER DEFAULT NULL,
    attribution_method TEXT DEFAULT '',
    visitor_type TEXT DEFAULT 'source_validation',
    stage TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    reason_text TEXT DEFAULT '',
    request_path TEXT DEFAULT '/',
    attempt_id TEXT DEFAULT '',
    classification TEXT NOT NULL DEFAULT 'rejected',
    resolution_status TEXT NOT NULL DEFAULT 'unresolved',
    resolved_at DATETIME DEFAULT NULL,
    resolved_visit_id TEXT DEFAULT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(partner_id) REFERENCES partners(id) ON DELETE SET NULL
  )`);
  const rejectionColumns = await all('PRAGMA table_info(inbound_rejection_logs)');
  const rejectionAuditMigrations = [
    ['attempt_id', "ALTER TABLE inbound_rejection_logs ADD COLUMN attempt_id TEXT DEFAULT ''"],
    ['classification', "ALTER TABLE inbound_rejection_logs ADD COLUMN classification TEXT NOT NULL DEFAULT 'rejected'"],
    ['resolution_status', "ALTER TABLE inbound_rejection_logs ADD COLUMN resolution_status TEXT NOT NULL DEFAULT 'unresolved'"],
    ['resolved_at', 'ALTER TABLE inbound_rejection_logs ADD COLUMN resolved_at DATETIME DEFAULT NULL'],
    ['resolved_visit_id', 'ALTER TABLE inbound_rejection_logs ADD COLUMN resolved_visit_id TEXT DEFAULT NULL']
  ];
  for (const [column, sql] of rejectionAuditMigrations) {
    if (!rejectionColumns.some(item => item.name === column)) await run(sql);
  }
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_rejection_last_seen ON inbound_rejection_logs(last_seen_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_rejection_lookup ON inbound_rejection_logs(client_ip, reason_code, partner_id, last_seen_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_rejection_visitor_lookup ON inbound_rejection_logs(visitor_hash, reason_code, partner_id, last_seen_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_inbound_rejection_resolution ON inbound_rejection_logs(classification, resolution_status, last_seen_at DESC)');
  await run(`CREATE TABLE IF NOT EXISTS inflow_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, partner_id INTEGER NOT NULL, ip TEXT NOT NULL,
    user_agent TEXT DEFAULT '', fingerprint TEXT DEFAULT '', is_compliant INTEGER DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(partner_id) REFERENCES partners(id) ON DELETE CASCADE
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_inflow_events_analytics ON inflow_events(partner_id, ip, timestamp)');
  await run('CREATE INDEX IF NOT EXISTS idx_inflow_events_timestamp ON inflow_events(timestamp)');
  await run(`CREATE TABLE IF NOT EXISTS outbound_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, link_id INTEGER NOT NULL, client_ip TEXT NOT NULL,
    source_partner_id INTEGER DEFAULT NULL, visit_id TEXT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(link_id) REFERENCES partners(id) ON DELETE CASCADE
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_outbound_time_link ON outbound_logs(created_at, link_id)');
  await run('CREATE INDEX IF NOT EXISTS idx_outbound_link_ip_time ON outbound_logs(link_id, client_ip, created_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_outbound_ip_time ON outbound_logs(client_ip, created_at)');
  const outboundColumns = await all('PRAGMA table_info(outbound_logs)');
  if (!outboundColumns.some(column => column.name === 'source_partner_id')) {
    await run('ALTER TABLE outbound_logs ADD COLUMN source_partner_id INTEGER DEFAULT NULL');
  }
  if (!outboundColumns.some(column => column.name === 'visit_id')) {
    await run('ALTER TABLE outbound_logs ADD COLUMN visit_id TEXT DEFAULT NULL');
  }
  await run('CREATE INDEX IF NOT EXISTS idx_outbound_source_visit_time ON outbound_logs(source_partner_id, visit_id, created_at)');

  // 一次性兼容迁移：旧版本存在双写表时，只补齐主事实表中缺失的历史记录。
  // 新安装不再创建 inflow_logs/outflow_logs，迁移后所有业务只读写 inbound_logs/outbound_logs。
  const legacyInflowTable = await get("SELECT 1 AS found FROM sqlite_master WHERE type = 'table' AND name = 'inflow_logs'");
  if (legacyInflowTable) {
    await run(`INSERT INTO inbound_logs(link_id, client_ip, user_agent, created_at)
      SELECT legacy.partner_id, legacy.ip, legacy.user_agent, legacy.timestamp
      FROM inflow_logs legacy
      WHERE NOT EXISTS (
        SELECT 1 FROM inbound_logs current
        WHERE current.link_id = legacy.partner_id
          AND current.client_ip = legacy.ip
          AND current.created_at = legacy.timestamp
      )`);
  }
  const legacyOutflowTable = await get("SELECT 1 AS found FROM sqlite_master WHERE type = 'table' AND name = 'outflow_logs'");
  if (legacyOutflowTable) {
    await run(`INSERT INTO outbound_logs(link_id, client_ip, created_at)
      SELECT legacy.partner_id, legacy.ip, legacy.timestamp
      FROM outflow_logs legacy
      WHERE NOT EXISTS (
        SELECT 1 FROM outbound_logs current
        WHERE current.link_id = legacy.partner_id
          AND current.client_ip = legacy.ip
          AND current.created_at = legacy.timestamp
      )`);
  }
  // 旧版 /go 曾写入 ISO 8601（T/Z）文本；统一为 SQLite UTC 格式，保证范围比较可使用索引。
  await run(`UPDATE inbound_logs
    SET created_at = substr(created_at, 1, 10) || ' ' || substr(created_at, 12, 8)
    WHERE substr(created_at, 11, 1) = 'T'`);
  await run(`UPDATE outbound_logs
    SET created_at = substr(created_at, 1, 10) || ' ' || substr(created_at, 12, 8)
    WHERE substr(created_at, 11, 1) = 'T'`);
  await run(`CREATE TABLE IF NOT EXISTS inflow_claim_tokens (
    token_hash TEXT PRIMARY KEY, partner_id INTEGER NOT NULL, ip TEXT NOT NULL,
    expires_at DATETIME NOT NULL, started_at_ms INTEGER NOT NULL DEFAULT 0, referer TEXT DEFAULT NULL,
    source_token_id INTEGER DEFAULT NULL, sid_partner_id INTEGER DEFAULT NULL,
    domain_partner_id INTEGER DEFAULT NULL, attribution_method TEXT DEFAULT 'domain_only',
    observed_domain TEXT DEFAULT '', user_agent TEXT DEFAULT '', visitor_hash TEXT DEFAULT '', request_path TEXT DEFAULT '/',
    claimed_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(partner_id) REFERENCES partners(id) ON DELETE CASCADE
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_claim_expires ON inflow_claim_tokens(expires_at)');

  const partnerColumns = await all('PRAGMA table_info(partners)');
  const partnerMigrations = [
    ['description', "ALTER TABLE partners ADD COLUMN description TEXT DEFAULT ''"],
    ['priority', 'ALTER TABLE partners ADD COLUMN priority INTEGER DEFAULT 0'],
    ['is_internal', 'ALTER TABLE partners ADD COLUMN is_internal INTEGER DEFAULT 0'],
    ['is_whitelisted', 'ALTER TABLE partners ADD COLUMN is_whitelisted INTEGER DEFAULT 0'],
    ['is_exempt', 'ALTER TABLE partners ADD COLUMN is_exempt INTEGER DEFAULT 0'],
    ['contact', "ALTER TABLE partners ADD COLUMN contact TEXT DEFAULT ''"],
    ['backlink_status', "ALTER TABLE partners ADD COLUMN backlink_status TEXT DEFAULT 'pending'"],
    ['backlink_url', 'ALTER TABLE partners ADD COLUMN backlink_url TEXT DEFAULT NULL'],
    ['last_checked_at', 'ALTER TABLE partners ADD COLUMN last_checked_at DATETIME DEFAULT NULL'],
    ['failed_check_count', 'ALTER TABLE partners ADD COLUMN failed_check_count INTEGER DEFAULT 0'],
    ['lost_count', 'ALTER TABLE partners ADD COLUMN lost_count INTEGER DEFAULT 0'],
    ['ping_exempt', 'ALTER TABLE partners ADD COLUMN ping_exempt INTEGER DEFAULT 0'],
    ['ping_failed_count', 'ALTER TABLE partners ADD COLUMN ping_failed_count INTEGER DEFAULT 0'],
    ['ping_status', "ALTER TABLE partners ADD COLUMN ping_status TEXT DEFAULT 'ok'"],
    ['last_ping_at', 'ALTER TABLE partners ADD COLUMN last_ping_at DATETIME DEFAULT NULL']
  ];
  for (const [column, sql] of partnerMigrations) {
    if (!partnerColumns.some(item => item.name === column)) await run(sql);
  }
  // source_marker 已由不可编辑的随机 SID 取代；先移除依赖索引，再安全删除旧列。
  await run('DROP INDEX IF EXISTS idx_partners_source_marker_unique');
  const currentPartnerColumns = await all('PRAGMA table_info(partners)');
  if (currentPartnerColumns.some(item => item.name === 'source_marker')) {
    await run('ALTER TABLE partners DROP COLUMN source_marker');
  }
  await run('CREATE INDEX IF NOT EXISTS idx_partners_internal ON partners(is_internal)');
  await run('CREATE INDEX IF NOT EXISTS idx_partners_whitelisted ON partners(is_whitelisted)');
  await run('CREATE INDEX IF NOT EXISTS idx_partners_exempt ON partners(is_exempt, is_approved)');
  await run('CREATE INDEX IF NOT EXISTS idx_partners_ping_exempt ON partners(ping_exempt, is_approved)');
  await run('UPDATE partners SET is_exempt = 1 WHERE is_internal = 1 AND COALESCE(is_exempt, 0) <> 1');
  await run("UPDATE partners SET backlink_status = 'pending' WHERE COALESCE(is_exempt, 0) = 0 AND (last_checked_at IS NULL OR last_checked_at = '') AND backlink_status = 'valid'");
  await run('DROP TRIGGER IF EXISTS trg_partners_unchecked_pending');
  await run(`CREATE TRIGGER trg_partners_unchecked_pending
    AFTER INSERT ON partners
    WHEN COALESCE(NEW.is_exempt, 0) = 0
      AND NEW.last_checked_at IS NULL
      AND (NEW.backlink_status IS NULL OR NEW.backlink_status = 'valid')
    BEGIN
      UPDATE partners SET backlink_status = 'pending' WHERE id = NEW.id;
    END`);

  const tokenColumns = await all('PRAGMA table_info(inflow_claim_tokens)');
  if (!tokenColumns.some(column => column.name === 'started_at_ms')) {
    await run('ALTER TABLE inflow_claim_tokens ADD COLUMN started_at_ms INTEGER NOT NULL DEFAULT 0');
  }
  if (!tokenColumns.some(column => column.name === 'referer')) {
    await run('ALTER TABLE inflow_claim_tokens ADD COLUMN referer TEXT DEFAULT NULL');
  }
  const claimAttributionMigrations = [
    ['source_token_id', 'ALTER TABLE inflow_claim_tokens ADD COLUMN source_token_id INTEGER DEFAULT NULL'],
    ['sid_partner_id', 'ALTER TABLE inflow_claim_tokens ADD COLUMN sid_partner_id INTEGER DEFAULT NULL'],
    ['domain_partner_id', 'ALTER TABLE inflow_claim_tokens ADD COLUMN domain_partner_id INTEGER DEFAULT NULL'],
    ['attribution_method', "ALTER TABLE inflow_claim_tokens ADD COLUMN attribution_method TEXT DEFAULT 'domain_only'"],
    ['observed_domain', "ALTER TABLE inflow_claim_tokens ADD COLUMN observed_domain TEXT DEFAULT ''"],
    ['user_agent', "ALTER TABLE inflow_claim_tokens ADD COLUMN user_agent TEXT DEFAULT ''"],
    ['visitor_hash', "ALTER TABLE inflow_claim_tokens ADD COLUMN visitor_hash TEXT DEFAULT ''"],
    ['request_path', "ALTER TABLE inflow_claim_tokens ADD COLUMN request_path TEXT DEFAULT '/'"],
    ['attempt_id', "ALTER TABLE inflow_claim_tokens ADD COLUMN attempt_id TEXT DEFAULT ''"]
  ];
  for (const [column, sql] of claimAttributionMigrations) {
    if (!tokenColumns.some(item => item.name === column)) await run(sql);
  }
  await run('CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, session_version INTEGER NOT NULL DEFAULT 0)');
  const adminColumns = await all('PRAGMA table_info(admins)');
  if (!adminColumns.some(column => column.name === 'session_version')) {
    await run('ALTER TABLE admins ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0');
  }
  await run(`CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, sort_order INTEGER NOT NULL DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  const missingCategories = await all(`SELECT DISTINCT TRIM(p.category) AS name
    FROM partners p LEFT JOIN categories c ON c.name = p.category
    WHERE TRIM(COALESCE(p.category, '')) <> '' AND c.id IS NULL`);
  if (missingCategories.length) {
    const maxCategoryOrder = await get('SELECT COALESCE(MAX(sort_order), -1) AS value FROM categories');
    for (let index = 0; index < missingCategories.length; index += 1) {
      await run('INSERT OR IGNORE INTO categories(name, sort_order) VALUES (?, ?)', [missingCategories[index].name, maxCategoryOrder.value + index + 1]);
    }
  }
  await run("CREATE TABLE IF NOT EXISTS site_configs (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
  await run(`CREATE TABLE IF NOT EXISTS risk_alert_states (
    partner_id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    first_detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_alerted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_alerted_fingerprint TEXT DEFAULT NULL,
    last_failed_at DATETIME DEFAULT NULL,
    last_failure_reason TEXT DEFAULT NULL,
    last_attempt_at DATETIME DEFAULT NULL,
    resolved_at DATETIME DEFAULT NULL,
    FOREIGN KEY(partner_id) REFERENCES partners(id) ON DELETE CASCADE
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_risk_alert_active ON risk_alert_states(resolved_at)');
  const riskAlertColumns = await all('PRAGMA table_info(risk_alert_states)');
  const riskAlertMigrations = [
    ['last_alerted_fingerprint', 'ALTER TABLE risk_alert_states ADD COLUMN last_alerted_fingerprint TEXT DEFAULT NULL'],
    ['last_failed_at', 'ALTER TABLE risk_alert_states ADD COLUMN last_failed_at DATETIME DEFAULT NULL'],
    ['last_failure_reason', 'ALTER TABLE risk_alert_states ADD COLUMN last_failure_reason TEXT DEFAULT NULL'],
    ['last_attempt_at', 'ALTER TABLE risk_alert_states ADD COLUMN last_attempt_at DATETIME DEFAULT NULL']
  ];
  for (const [column, sql] of riskAlertMigrations) {
    if (!riskAlertColumns.some(item => item.name === column)) await run(sql);
  }
  await run(`UPDATE risk_alert_states SET last_alerted_fingerprint = fingerprint
    WHERE last_alerted_fingerprint IS NULL AND last_alerted_at IS NOT NULL`);
  await run(`CREATE TABLE IF NOT EXISTS webhook_delivery_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    is_fallback INTEGER NOT NULL DEFAULT 0,
    success INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER DEFAULT NULL,
    error_code TEXT DEFAULT NULL,
    error_message TEXT DEFAULT NULL,
    duration_ms INTEGER DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_webhook_delivery_created ON webhook_delivery_logs(created_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_webhook_delivery_provider_success_time ON webhook_delivery_logs(provider, success, created_at DESC)');

  const initialPassword = INITIAL_ADMIN_PASSWORD || 'admin123';
  const adminCount = await get('SELECT COUNT(*) AS count FROM admins');
  if (Number(adminCount.count) === 0) {
    await run("INSERT INTO admins(username, password_hash) VALUES('admin', ?)", [await bcrypt.hash(initialPassword, 12)]);
    if (!INITIAL_ADMIN_PASSWORD) console.warn('【安全提示】总后台接管前可使用引导账号 admin / admin123；请尽快完成总后台接入。');
  }

  for (const [key, value] of Object.entries(CONFIG_DEFAULTS)) {
    await run('INSERT OR IGNORE INTO site_configs(key, value) VALUES (?, ?)', [key, value]);
  }
  for (const [key, value] of Object.entries(INTEGRATION_STATE_DEFAULTS)) {
    await run('INSERT OR IGNORE INTO site_configs(key, value) VALUES (?, ?)', [key, value]);
  }
  const integrationState = await getIntegrationState();
  if (!CONTROL_CENTER_ENABLED
    && integrationState.control_center_enrolled !== '1'
    && integrationState.bootstrap_password_active === '1') {
    const admin = await getAdminByUsername('admin', 'password');
    if (admin && !(await bcrypt.compare(initialPassword, admin.password_hash))) {
      await updateAdminPassword(admin.id, await bcrypt.hash(initialPassword, 12));
    }
  }
  const contactEmail = await configValue('contact_email');
  const legacyEmail = await configValue('lost_prevention_email');
  if (!contactEmail && legacyEmail) await upsertConfig('contact_email', legacyEmail);
  // 高频流水清理由 jobs/cron.js 统一调度，避免启动阶段一次性 DELETE 锁表。
}

module.exports = {
  CONFIG_DEFAULTS,
  RISK_CONTROL_CONFIG_KEYS,
  configValue,
  getConfigValues,
  getAllConfig,
  getRiskControlConfig,
  upsertConfig,
  upsertConfigs,
  getAdminByUsername,
  getAdminSessionById,
  updateAdminPassword,
  getIntegrationState,
  completeControlCenterEnrollment,
  listCategories,
  listAdminCategories,
  categoryExists,
  createCategory,
  saveCategoryOrder,
  deleteCategory,
  runDatabaseMaintenance,
  initializeDatabase
};
