'use strict';

const crypto = require('crypto');
const { run, get, all, withTransaction } = require('../config/database');

const SETTING_FIELDS = new Set([
  'enabled', 'recovery_email', 'recovery_publish_url', 'recovery_contact',
  'recovery_message', 'found_message', 'manifest_valid_days', 'max_domains',
  'probe_timeout_ms', 'probe_concurrency', 'name', 'status'
]);

const RESOLVER_CATALOG = Object.freeze([
  ['dnspod', 'DNSPod', 'https://doh.pub/dns-query', 'wire', '中国大陆主线路'],
  ['alidns', 'AliDNS', 'https://dns.alidns.com/dns-query', 'wire', '中国大陆主线路'],
  ['cloudflare', 'Cloudflare', 'https://cloudflare-dns.com/dns-query', 'wire', '全球主力'],
  ['google', 'Google Public DNS', 'https://dns.google/dns-query', 'wire', '全球主力'],
  ['quad9-unfiltered', 'Quad9 No-block', 'https://dns10.quad9.net/dns-query', 'wire', '全球主力'],
  ['adguard-unfiltered', 'AdGuard Unfiltered', 'https://unfiltered.adguard-dns.com/dns-query', 'wire', '扩展容灾'],
  ['mullvad', 'Mullvad DNS', 'https://dns.mullvad.net/dns-query', 'wire', '扩展容灾'],
  ['controld-free', 'Control D Free', 'https://freedns.controld.com/p0', 'wire', '扩展容灾']
]);

// RFC 1035 limits one TXT character-string to 255 octets.  The recovery
// publisher deliberately stays below that boundary instead of relying on a
// provider UI/API to split an oversized value differently.
const AUTHORITATIVE_DNS_CATALOG = Object.freeze([
  ['cloudflare', 'Cloudflare DNS', 'automatic', 255, 240, '支持多个 API 通道自动发布；单字符串 255 字节，系统使用 240 字节安全上限'],
  ['desec', 'deSEC', 'automatic', 255, 240, '支持多个 API Token 通道自动发布；单字符串 255 字节'],
  ['cloudns', 'ClouDNS（HTTP API 需付费套餐）', 'automatic', 255, 240, '自动发布依赖 ClouDNS Premium DNS 或其他包含 HTTP API 的付费套餐；免费套餐只能手动管理 DNS'],
  ['route53', 'AWS Route 53', 'automatic', 255, 240, '支持多个 AWS 凭据通道自动发布；单字符串 255 字节'],
  ['dnspod', '腾讯云 DNSPod', 'automatic', 255, 240, '支持多个腾讯云 API 密钥通道；按 DNS 单字符串 255 字节、系统 240 字节发布'],
  ['aliyun', '阿里云云解析 DNS', 'automatic', 512, 240, '控制台支持最多 512 个字符；系统仍使用跨平台 240 字节安全上限'],
  ['baidu', '百度智能云 DNS', 'automatic', 255, 240, '官方 TXT 记录值上限 255 字符；系统使用 240 字节安全上限'],
  ['volcengine', '火山引擎 DNS', 'automatic', 255, 240, '公共 DNS 使用跨平台 255 字节边界；系统使用 240 字节安全上限'],
  ['he', 'Hurricane Electric Free DNS', 'manual', 255, 240, '免费 DNS 以手动发布为主；使用跨平台 240 字节安全上限']
]);

async function ensureColumn(table, name, definition) {
  const columns = await all(`PRAGMA table_info(${table})`);
  if (!columns.some(column => column.name === name)) await run(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
}

async function migrateScopedUniqueTables() {
  const domainSchema = await get(`SELECT sql FROM sqlite_master WHERE type='table' AND name='recovery_domains'`);
  if (/url\s+TEXT\s+NOT\s+NULL\s+UNIQUE/i.test(domainSchema?.sql || '')) {
    await withTransaction(async transaction => {
      await transaction.run(`CREATE TABLE recovery_domains_scoped (
        id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL DEFAULT 1,
        title TEXT NOT NULL, url TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 0,
        status INTEGER NOT NULL DEFAULT 1, last_probe_status TEXT NOT NULL DEFAULT 'untested',
        last_probe_ms INTEGER DEFAULT NULL, last_probe_error TEXT NOT NULL DEFAULT '',
        last_probe_at DATETIME DEFAULT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(profile_id, url))`);
      await transaction.run(`INSERT INTO recovery_domains_scoped SELECT id,profile_id,title,url,priority,status,last_probe_status,last_probe_ms,last_probe_error,last_probe_at,created_at,updated_at FROM recovery_domains`);
      await transaction.run('DROP TABLE recovery_domains');
      await transaction.run('ALTER TABLE recovery_domains_scoped RENAME TO recovery_domains');
    }, { durability: 'full', label: 'scope recovery domain uniqueness' });
  }
  const bootstrapSchema = await get(`SELECT sql FROM sqlite_master WHERE type='table' AND name='recovery_bootstrap_records'`);
  if (/record_name\s+TEXT\s+NOT\s+NULL\s+UNIQUE/i.test(bootstrapSchema?.sql || '')) {
    await withTransaction(async transaction => {
      await transaction.run(`CREATE TABLE recovery_bootstrap_records_scoped (
        id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL DEFAULT 1,
        label TEXT NOT NULL, record_name TEXT NOT NULL, zone_name TEXT NOT NULL,
        is_primary INTEGER NOT NULL DEFAULT 0, status INTEGER NOT NULL DEFAULT 1,
        sort_order INTEGER NOT NULL DEFAULT 0, last_publish_status TEXT NOT NULL DEFAULT 'unpublished',
        last_publish_error TEXT NOT NULL DEFAULT '', last_published_generation INTEGER NOT NULL DEFAULT 0,
        last_published_at DATETIME DEFAULT NULL, last_verified_at DATETIME DEFAULT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(profile_id, record_name))`);
      await transaction.run(`INSERT INTO recovery_bootstrap_records_scoped SELECT id,profile_id,label,record_name,zone_name,is_primary,status,sort_order,last_publish_status,last_publish_error,last_published_generation,last_published_at,last_verified_at,created_at,updated_at FROM recovery_bootstrap_records`);
      await transaction.run('DROP TABLE recovery_bootstrap_records');
      await transaction.run('ALTER TABLE recovery_bootstrap_records_scoped RENAME TO recovery_bootstrap_records');
    }, { durability: 'full', label: 'scope recovery bootstrap uniqueness' });
  }
}

async function initializeRecoveryTables() {
  await run(`CREATE TABLE IF NOT EXISTS recovery_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1), enabled INTEGER NOT NULL DEFAULT 0,
    project_id TEXT NOT NULL DEFAULT '', recovery_email TEXT NOT NULL DEFAULT '',
    recovery_publish_url TEXT NOT NULL DEFAULT '', recovery_contact TEXT NOT NULL DEFAULT '',
    recovery_message TEXT NOT NULL DEFAULT '请保存最新地址，谨防仿冒网站。',
    found_message TEXT NOT NULL DEFAULT '该地址已经过恢复清单签名和动态线路检测。',
    current_generation INTEGER NOT NULL DEFAULT 0, public_key_id TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL DEFAULT '', next_public_key_id TEXT NOT NULL DEFAULT '',
    next_public_key TEXT NOT NULL DEFAULT '', manifest_valid_days INTEGER NOT NULL DEFAULT 90,
    max_domains INTEGER NOT NULL DEFAULT 10, probe_timeout_ms INTEGER NOT NULL DEFAULT 3000,
    probe_concurrency INTEGER NOT NULL DEFAULT 3, component_version TEXT NOT NULL DEFAULT 'recovery-v1',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`INSERT OR IGNORE INTO recovery_settings(id, project_id) VALUES (1, ?)`,
    [`navigation-recovery-${crypto.randomBytes(6).toString('hex')}`]);

  await run(`CREATE TABLE IF NOT EXISTS recovery_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active', enabled INTEGER NOT NULL DEFAULT 0,
    project_id TEXT NOT NULL UNIQUE, recovery_email TEXT NOT NULL DEFAULT '',
    recovery_publish_url TEXT NOT NULL DEFAULT '', recovery_contact TEXT NOT NULL DEFAULT '',
    recovery_message TEXT NOT NULL DEFAULT '请保存最新地址，谨防仿冒网站。',
    found_message TEXT NOT NULL DEFAULT '该地址已经过恢复清单签名和动态线路检测。',
    current_generation INTEGER NOT NULL DEFAULT 0, public_key_id TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL DEFAULT '', next_public_key_id TEXT NOT NULL DEFAULT '',
    next_public_key TEXT NOT NULL DEFAULT '', manifest_valid_days INTEGER NOT NULL DEFAULT 90,
    max_domains INTEGER NOT NULL DEFAULT 10, probe_timeout_ms INTEGER NOT NULL DEFAULT 3000,
    probe_concurrency INTEGER NOT NULL DEFAULT 3, component_version TEXT NOT NULL DEFAULT 'recovery-v2',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  const legacy = await get('SELECT * FROM recovery_settings WHERE id = 1');
  await run(`INSERT OR IGNORE INTO recovery_profiles(
      id, name, code, enabled, project_id, recovery_email, recovery_publish_url, recovery_contact,
      recovery_message, found_message, current_generation, public_key_id, public_key,
      next_public_key_id, next_public_key, manifest_valid_days, max_domains,
      probe_timeout_ms, probe_concurrency, component_version, updated_at)
    VALUES (1, '默认恢复方案', 'default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'recovery-v2', CURRENT_TIMESTAMP)`, [
    legacy.enabled, legacy.project_id, legacy.recovery_email, legacy.recovery_publish_url,
    legacy.recovery_contact, legacy.recovery_message, legacy.found_message,
    legacy.current_generation, legacy.public_key_id, legacy.public_key,
    legacy.next_public_key_id, legacy.next_public_key, legacy.manifest_valid_days,
    legacy.max_domains, legacy.probe_timeout_ms, legacy.probe_concurrency
  ]);

  await run(`CREATE TABLE IF NOT EXISTS recovery_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL DEFAULT 1,
    title TEXT NOT NULL, url TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0, status INTEGER NOT NULL DEFAULT 1,
    last_probe_status TEXT NOT NULL DEFAULT 'untested', last_probe_ms INTEGER DEFAULT NULL,
    last_probe_error TEXT NOT NULL DEFAULT '', last_probe_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(profile_id, url)
  )`);
  await ensureColumn('recovery_domains', 'profile_id', 'INTEGER NOT NULL DEFAULT 1');
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_domains_profile ON recovery_domains(profile_id, status, priority DESC, id ASC)');

  await run(`CREATE TABLE IF NOT EXISTS recovery_bootstrap_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL DEFAULT 1,
    label TEXT NOT NULL, record_name TEXT NOT NULL,
    zone_name TEXT NOT NULL, is_primary INTEGER NOT NULL DEFAULT 0, status INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0, last_publish_status TEXT NOT NULL DEFAULT 'unpublished',
    last_publish_error TEXT NOT NULL DEFAULT '', last_published_generation INTEGER NOT NULL DEFAULT 0,
    last_published_at DATETIME DEFAULT NULL, last_verified_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(profile_id, record_name)
  )`);
  await ensureColumn('recovery_bootstrap_records', 'profile_id', 'INTEGER NOT NULL DEFAULT 1');
  await migrateScopedUniqueTables();
  await ensureColumn('recovery_bootstrap_records', 'provider_id', "TEXT NOT NULL DEFAULT 'cloudflare'");
  await ensureColumn('recovery_bootstrap_records', 'share_role', "TEXT NOT NULL DEFAULT 'LEGACY'");
  await ensureColumn('recovery_bootstrap_records', 'publish_mode', "TEXT NOT NULL DEFAULT 'automatic'");
  await ensureColumn('recovery_bootstrap_records', 'dns_channel_id', 'INTEGER DEFAULT NULL');
  await ensureColumn('recovery_bootstrap_records', 'provider_zone_id', "TEXT NOT NULL DEFAULT ''");
  await ensureColumn('recovery_bootstrap_records', 'group_id', 'INTEGER DEFAULT NULL');
  await ensureColumn('recovery_bootstrap_records', 'required_target', 'INTEGER NOT NULL DEFAULT 0');
  await run(`CREATE TABLE IF NOT EXISTS recovery_bootstrap_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL DEFAULT 1,
    label TEXT NOT NULL, compatibility_mode TEXT NOT NULL DEFAULT 'AB_R1',
    status INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(profile_id) REFERENCES recovery_profiles(id) ON DELETE CASCADE
  )`);
  await run(`CREATE TABLE IF NOT EXISTS recovery_bootstrap_group_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL DEFAULT 1,
    group_id INTEGER NOT NULL, title TEXT NOT NULL, url TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0, status INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(group_id, url),
    FOREIGN KEY(profile_id) REFERENCES recovery_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY(group_id) REFERENCES recovery_bootstrap_groups(id) ON DELETE CASCADE
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_domains_profile ON recovery_domains(profile_id, status, priority DESC, id ASC)');
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_bootstrap_profile ON recovery_bootstrap_records(profile_id, status, is_primary, sort_order, id)');
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_bootstrap_group ON recovery_bootstrap_records(profile_id, group_id, share_role, id)');
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_bootstrap_group_domains ON recovery_bootstrap_group_domains(profile_id, group_id, status, priority DESC, id)');

  await run(`CREATE TABLE IF NOT EXISTS recovery_dns_providers (
    id TEXT PRIMARY KEY, label TEXT NOT NULL, default_publish_mode TEXT NOT NULL,
    max_character_string_bytes INTEGER NOT NULL DEFAULT 255,
    portable_record_bytes INTEGER NOT NULL DEFAULT 240,
    note TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  for (const item of AUTHORITATIVE_DNS_CATALOG) {
    await run(`INSERT INTO recovery_dns_providers(id,label,default_publish_mode,max_character_string_bytes,portable_record_bytes,note,enabled)
      VALUES(?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET label=excluded.label,
      default_publish_mode=excluded.default_publish_mode,max_character_string_bytes=excluded.max_character_string_bytes,
      portable_record_bytes=excluded.portable_record_bytes,note=excluded.note`, item);
  }

  await run(`CREATE TABLE IF NOT EXISTS recovery_dns_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL DEFAULT 1,
    provider_id TEXT NOT NULL, label TEXT NOT NULL, credential_key TEXT NOT NULL UNIQUE,
    account_hint TEXT NOT NULL DEFAULT '', status INTEGER NOT NULL DEFAULT 1,
    last_test_status TEXT NOT NULL DEFAULT 'untested', last_test_error TEXT NOT NULL DEFAULT '',
    last_test_at DATETIME DEFAULT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(profile_id, label),
    FOREIGN KEY(profile_id) REFERENCES recovery_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY(provider_id) REFERENCES recovery_dns_providers(id)
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_dns_channels_profile ON recovery_dns_channels(profile_id, provider_id, status, id)');

  await run(`CREATE TABLE IF NOT EXISTS recovery_resolvers (
    id TEXT PRIMARY KEY, label TEXT NOT NULL, endpoint TEXT NOT NULL, response_format TEXT NOT NULL DEFAULT 'wire',
    category TEXT NOT NULL DEFAULT '', built_in INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  for (const item of RESOLVER_CATALOG) {
    await run(`INSERT INTO recovery_resolvers(id, label, endpoint, response_format, category, built_in, enabled)
      VALUES (?, ?, ?, ?, ?, 1, 1) ON CONFLICT(id) DO UPDATE SET label=excluded.label,
      endpoint=excluded.endpoint, response_format=excluded.response_format, category=excluded.category`, item);
  }

  await run(`CREATE TABLE IF NOT EXISTS recovery_lookup_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL, resolver_id TEXT NOT NULL,
    bootstrap_id INTEGER NOT NULL, priority_group INTEGER NOT NULL DEFAULT 1,
    timeout_ms INTEGER NOT NULL DEFAULT 2500, sort_order INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 1, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(profile_id, resolver_id, bootstrap_id),
    FOREIGN KEY(profile_id) REFERENCES recovery_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY(resolver_id) REFERENCES recovery_resolvers(id),
    FOREIGN KEY(bootstrap_id) REFERENCES recovery_bootstrap_records(id) ON DELETE CASCADE
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_lookup_routes_profile ON recovery_lookup_routes(profile_id, status, priority_group, sort_order, id)');

  await run(`CREATE TABLE IF NOT EXISTS recovery_releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT, generation INTEGER NOT NULL UNIQUE,
    payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL, signature TEXT NOT NULL,
    key_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL, published_at DATETIME DEFAULT NULL,
    source_release_id INTEGER DEFAULT NULL, publish_error TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(source_release_id) REFERENCES recovery_releases(id) ON DELETE SET NULL
  )`);
  await ensureColumn('recovery_releases', 'profile_id', 'INTEGER NOT NULL DEFAULT 1');
  await ensureColumn('recovery_releases', 'dns_payloads_json', "TEXT NOT NULL DEFAULT '[]'");
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_releases_profile ON recovery_releases(profile_id, status, generation DESC)');

  await run(`CREATE TABLE IF NOT EXISTS recovery_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, detail_json TEXT NOT NULL DEFAULT '{}',
    success INTEGER NOT NULL DEFAULT 1, error_message TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await ensureColumn('recovery_audit_logs', 'profile_id', 'INTEGER NOT NULL DEFAULT 1');
  await run('CREATE INDEX IF NOT EXISTS idx_recovery_audit_profile ON recovery_audit_logs(profile_id, created_at DESC)');
}

const profileId = value => Math.max(1, Number.parseInt(value, 10) || 1);
function listProfiles() { return all(`SELECT * FROM recovery_profiles WHERE status <> 'deleted' ORDER BY id ASC`); }
function getProfile(id = 1) { return get('SELECT * FROM recovery_profiles WHERE id = ?', [profileId(id)]); }
function getSettings(id = 1) { return getProfile(id); }

async function createProfile(input = {}) {
  const name = String(input.name || '').trim();
  const code = String(input.code || '').trim().toLowerCase();
  if (!name || name.length > 80) throw new Error('方案名称需为 1 到 80 个字符');
  if (!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(code)) throw new Error('方案标识只能使用小写字母、数字、连字符或下划线');
  const result = await run(`INSERT INTO recovery_profiles(name, code, project_id)
    VALUES (?, ?, ?)`, [name, code, `navigation-recovery-${crypto.randomBytes(8).toString('hex')}`]);
  return getProfile(result.id);
}

async function updateSettings(input = {}, id = 1) {
  const entries = Object.entries(input).filter(([key]) => SETTING_FIELDS.has(key));
  if (!entries.length) return getSettings(id);
  await run(`UPDATE recovery_profiles SET ${entries.map(([key]) => `${key} = ?`).join(', ')},
    updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [...entries.map(([, value]) => value), profileId(id)]);
  return getSettings(id);
}

async function saveKeyState(fields = {}, id = 1) {
  const allowed = ['public_key_id', 'public_key', 'next_public_key_id', 'next_public_key'];
  const entries = Object.entries(fields).filter(([key]) => allowed.includes(key));
  if (!entries.length) return getSettings(id);
  await run(`UPDATE recovery_profiles SET ${entries.map(([key]) => `${key} = ?`).join(', ')},
    updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [...entries.map(([, value]) => value), profileId(id)]);
  return getSettings(id);
}

function listDomains({ enabledOnly = false, profileId: owner = 1 } = {}) {
  return all(`SELECT * FROM recovery_domains WHERE profile_id = ? ${enabledOnly ? 'AND status = 1' : ''}
    ORDER BY priority DESC, id ASC`, [profileId(owner)]);
}
function getDomain(id, owner = null) { return owner ? get('SELECT * FROM recovery_domains WHERE id = ? AND profile_id = ?', [id, profileId(owner)]) : get('SELECT * FROM recovery_domains WHERE id = ?', [id]); }
async function createDomain(input, owner = 1) { const result = await run(`INSERT INTO recovery_domains(profile_id,title,url,priority,status) VALUES(?,?,?,?,?)`, [profileId(owner), input.title, input.url, input.priority, input.status]); return getDomain(result.id); }
async function updateDomain(id, input, owner = null) { await run(`UPDATE recovery_domains SET title=?,url=?,priority=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?${owner ? ' AND profile_id=?' : ''}`, [input.title,input.url,input.priority,input.status,id,...(owner ? [profileId(owner)] : [])]); return getDomain(id); }
function deleteDomain(id, owner = null) { return run(`DELETE FROM recovery_domains WHERE id=?${owner ? ' AND profile_id=?' : ''}`, [id,...(owner ? [profileId(owner)] : [])]); }
async function saveProbeResult(id, result) { await run(`UPDATE recovery_domains SET last_probe_status=?,last_probe_ms=?,last_probe_error=?,last_probe_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?`, [result.healthy?'healthy':'failed',result.elapsedMs??null,result.error||'',id]); return getDomain(id); }

function listBootstrapGroups(owner = 1) { return all('SELECT * FROM recovery_bootstrap_groups WHERE profile_id=? ORDER BY id',[profileId(owner)]); }
function getBootstrapGroup(id,owner=null){return owner?get('SELECT * FROM recovery_bootstrap_groups WHERE id=? AND profile_id=?',[id,profileId(owner)]):get('SELECT * FROM recovery_bootstrap_groups WHERE id=?',[id]);}
function listBootstrapGroupDomains({groupId=null,enabledOnly=false,profileId:owner=1}={}){return all(`SELECT * FROM recovery_bootstrap_group_domains WHERE profile_id=? ${groupId?'AND group_id=?':''} ${enabledOnly?'AND status=1':''} ORDER BY group_id,priority DESC,id`,[profileId(owner),...(groupId?[Number(groupId)]:[])]);}
function listBootstrapRecords({ enabledOnly = false, profileId: owner = 1 } = {}) { return all(`SELECT b.*,p.label AS provider_label,p.max_character_string_bytes,p.portable_record_bytes,p.note AS provider_note,c.label AS channel_label,c.account_hint AS channel_account_hint,c.status AS channel_status,g.label AS group_label,g.compatibility_mode AS group_compatibility_mode FROM recovery_bootstrap_records b LEFT JOIN recovery_dns_providers p ON p.id=b.provider_id LEFT JOIN recovery_dns_channels c ON c.id=b.dns_channel_id LEFT JOIN recovery_bootstrap_groups g ON g.id=b.group_id WHERE b.profile_id=? ${enabledOnly ? 'AND b.status=1' : ''} ORDER BY COALESCE(b.group_id,2147483647),CASE b.share_role WHEN 'A' THEN 0 WHEN 'B' THEN 1 ELSE 2 END,b.sort_order,b.id`, [profileId(owner)]); }
function getBootstrapRecord(id, owner = null) { return owner ? get('SELECT * FROM recovery_bootstrap_records WHERE id=? AND profile_id=?',[id,profileId(owner)]) : get('SELECT * FROM recovery_bootstrap_records WHERE id=?',[id]); }
async function createBootstrapRecord(input, owner = 1) { const result=await run(`INSERT INTO recovery_bootstrap_records(profile_id,label,record_name,zone_name,is_primary,status,sort_order,provider_id,share_role,publish_mode,dns_channel_id,provider_zone_id,group_id,required_target) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,[profileId(owner),input.label,input.recordName,input.zoneName,input.isPrimary,input.status,input.sortOrder,input.providerId,input.shareRole,input.publishMode,input.dnsChannelId||null,input.providerZoneId||'',input.groupId||null,input.requiredTarget?1:0]); return getBootstrapRecord(result.id); }
async function updateBootstrapRecord(id,input,owner=null){const current=await getBootstrapRecord(id,owner);await run(`UPDATE recovery_bootstrap_records SET label=?,record_name=?,zone_name=?,is_primary=?,status=?,sort_order=?,provider_id=?,share_role=?,publish_mode=?,dns_channel_id=?,provider_zone_id=?,group_id=?,required_target=?,updated_at=CURRENT_TIMESTAMP WHERE id=?${owner?' AND profile_id=?':''}`,[input.label,input.recordName,input.zoneName,input.isPrimary,input.status,input.sortOrder,input.providerId,input.shareRole,input.publishMode,input.dnsChannelId||null,input.providerZoneId||'',input.groupId===undefined?(current?.group_id||null):(input.groupId||null),input.requiredTarget===undefined?Number(current?.required_target||0):(input.requiredTarget?1:0),id,...(owner?[profileId(owner)]:[])]);return getBootstrapRecord(id);}
function deleteBootstrapRecord(id,owner=null){return run(`DELETE FROM recovery_bootstrap_records WHERE id=?${owner?' AND profile_id=?':''}`,[id,...(owner?[profileId(owner)]:[])]);}
async function saveBootstrapPublishResult(id,result){await run(`UPDATE recovery_bootstrap_records SET last_publish_status=?,last_publish_error=?,last_published_generation=CASE WHEN ?>0 THEN ? ELSE last_published_generation END,last_published_at=CASE WHEN ?>0 THEN CURRENT_TIMESTAMP ELSE last_published_at END,last_verified_at=CASE WHEN ?=1 THEN CURRENT_TIMESTAMP ELSE last_verified_at END,updated_at=CURRENT_TIMESTAMP WHERE id=?`,[result.status,result.error||'',result.generation||0,result.generation||0,result.generation||0,result.verified?1:0,id]);}

async function createBootstrapGroup(input, records, domains, owner = 1) {
  return withTransaction(async transaction => {
    const groupResult = await transaction.run(`INSERT INTO recovery_bootstrap_groups(profile_id,label,compatibility_mode,status) VALUES(?,?,?,?)`,[profileId(owner),input.label,input.compatibilityMode,input.status]);
    for (const domain of domains) {
      await transaction.run(`INSERT INTO recovery_bootstrap_group_domains(profile_id,group_id,title,url,priority,status) VALUES(?,?,?,?,?,?)`,[profileId(owner),groupResult.id,domain.title,domain.url,domain.priority,domain.status]);
    }
    for (const record of records) {
      await transaction.run(`INSERT INTO recovery_bootstrap_records(profile_id,label,record_name,zone_name,is_primary,status,sort_order,provider_id,share_role,publish_mode,dns_channel_id,provider_zone_id,group_id,required_target) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,[profileId(owner),record.label,record.recordName,record.zoneName,record.isPrimary,record.status,record.sortOrder,record.providerId,record.shareRole,record.publishMode,record.dnsChannelId||null,record.providerZoneId||'',groupResult.id,record.requiredTarget?1:0]);
    }
    return transaction.get('SELECT * FROM recovery_bootstrap_groups WHERE id=?',[groupResult.id]);
  },{durability:'full',label:'create recovery bootstrap group'});
}
async function deleteBootstrapGroup(id,owner=1){return withTransaction(async transaction=>{await transaction.run('DELETE FROM recovery_lookup_routes WHERE bootstrap_id IN (SELECT id FROM recovery_bootstrap_records WHERE group_id=? AND profile_id=?)',[id,profileId(owner)]);await transaction.run('DELETE FROM recovery_bootstrap_records WHERE group_id=? AND profile_id=?',[id,profileId(owner)]);return transaction.run('DELETE FROM recovery_bootstrap_groups WHERE id=? AND profile_id=?',[id,profileId(owner)]);},{durability:'full',label:'delete recovery bootstrap group'});}

function listResolvers(){return all('SELECT * FROM recovery_resolvers WHERE enabled=1 ORDER BY category,label');}
function listDnsProviders(){return all('SELECT * FROM recovery_dns_providers WHERE enabled=1 ORDER BY label');}
function getDnsProvider(id){return get('SELECT * FROM recovery_dns_providers WHERE id=? AND enabled=1',[id]);}
function listDnsChannels(owner=1,{enabledOnly=false}={}){return all(`SELECT c.*,p.label AS provider_label,p.default_publish_mode,p.note AS provider_note FROM recovery_dns_channels c JOIN recovery_dns_providers p ON p.id=c.provider_id WHERE c.profile_id=? ${enabledOnly?'AND c.status=1':''} ORDER BY p.label,c.label,c.id`,[profileId(owner)]);}
function getDnsChannel(id,owner=null){return owner?get('SELECT * FROM recovery_dns_channels WHERE id=? AND profile_id=?',[id,profileId(owner)]):get('SELECT * FROM recovery_dns_channels WHERE id=?',[id]);}
function getDnsChannelByCredentialKey(key){return get('SELECT * FROM recovery_dns_channels WHERE credential_key=?',[key]);}
async function createDnsChannel(input,owner=1){const result=await run(`INSERT INTO recovery_dns_channels(profile_id,provider_id,label,credential_key,account_hint,status) VALUES(?,?,?,?,?,?)`,[profileId(owner),input.providerId,input.label,input.credentialKey,input.accountHint||'',input.status]);return getDnsChannel(result.id);}
async function updateDnsChannel(id,input,owner=1){await run(`UPDATE recovery_dns_channels SET provider_id=?,label=?,account_hint=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND profile_id=?`,[input.providerId,input.label,input.accountHint||'',input.status,id,profileId(owner)]);return getDnsChannel(id,owner);}
async function saveDnsChannelTestResult(id,result){await run(`UPDATE recovery_dns_channels SET last_test_status=?,last_test_error=?,last_test_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?`,[result.ok?'healthy':'failed',result.error||'',id]);return getDnsChannel(id);}
function countDnsChannelReferences(id){return get('SELECT COUNT(*) AS count FROM recovery_bootstrap_records WHERE dns_channel_id=?',[id]);}
function deleteDnsChannel(id,owner=1){return run('DELETE FROM recovery_dns_channels WHERE id=? AND profile_id=?',[id,profileId(owner)]);}
function assignDnsChannelToLegacyCloudflare(channelId,owner=1){return run(`UPDATE recovery_bootstrap_records SET dns_channel_id=? WHERE profile_id=? AND provider_id='cloudflare' AND publish_mode='automatic' AND dns_channel_id IS NULL`,[channelId,profileId(owner)]);}
function getResolver(id){return get('SELECT * FROM recovery_resolvers WHERE id=? AND enabled=1',[id]);}
function listLookupRoutes(owner=1,{enabledOnly=false}={}){return all(`SELECT r.*,d.label AS resolver_label,d.endpoint,d.response_format,b.label AS bootstrap_label,b.record_name FROM recovery_lookup_routes r JOIN recovery_resolvers d ON d.id=r.resolver_id JOIN recovery_bootstrap_records b ON b.id=r.bootstrap_id WHERE r.profile_id=? ${enabledOnly?'AND r.status=1 AND d.enabled=1 AND b.status=1':''} ORDER BY r.priority_group,r.sort_order,r.id`,[profileId(owner)]);}
async function createLookupRoute(input,owner=1){const result=await run(`INSERT INTO recovery_lookup_routes(profile_id,resolver_id,bootstrap_id,priority_group,timeout_ms,sort_order,status) VALUES(?,?,?,?,?,?,?)`,[profileId(owner),input.resolverId,input.bootstrapId,input.priorityGroup,input.timeoutMs,input.sortOrder,input.status]);return get('SELECT * FROM recovery_lookup_routes WHERE id=?',[result.id]);}
function deleteLookupRoute(id,owner=1){return run('DELETE FROM recovery_lookup_routes WHERE id=? AND profile_id=?',[id,profileId(owner)]);}

async function nextGeneration(owner=1){const row=await get('SELECT MAX(generation) AS generation FROM recovery_releases');const settings=await getSettings(owner);return Math.max(Number(row?.generation||0),Number(settings?.current_generation||0))+1;}
async function createRelease(input,owner=1){const result=await run(`INSERT INTO recovery_releases(profile_id,generation,payload_json,payload_hash,signature,key_id,status,issued_at,expires_at,source_release_id,dns_payloads_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,[profileId(owner),input.generation,input.payloadJson,input.payloadHash,input.signature,input.keyId,input.status||'draft',input.issuedAt,input.expiresAt,input.sourceReleaseId||null,input.dnsPayloadsJson||'[]']);return getRelease(result.id);}
function getRelease(id,owner=null){return owner?get('SELECT * FROM recovery_releases WHERE id=? AND profile_id=?',[id,profileId(owner)]):get('SELECT * FROM recovery_releases WHERE id=?',[id]);}
function getReleaseByGeneration(generation,owner=1){return get('SELECT * FROM recovery_releases WHERE generation=? AND profile_id=?',[generation,profileId(owner)]);}
function listReleases(limit=50,owner=1){return all('SELECT * FROM recovery_releases WHERE profile_id=? ORDER BY generation DESC LIMIT ?',[profileId(owner),Math.max(1,Math.min(200,Number(limit)||50))]);}
function getLatestPublishedRelease(owner=1){return get(`SELECT * FROM recovery_releases WHERE profile_id=? AND status='published' ORDER BY generation DESC LIMIT 1`,[profileId(owner)]);}
async function markRelease(id,status,fields={}){const published=status==='published'?', published_at=CURRENT_TIMESTAMP':'';await run(`UPDATE recovery_releases SET status=?,publish_error=?${published} WHERE id=?`,[status,fields.error||'',id]);return getRelease(id);}
async function publishReleaseAtomically(id,generation,owner=1){return withTransaction(async({run:txRun})=>{await txRun(`UPDATE recovery_releases SET status='superseded' WHERE profile_id=? AND status='published' AND id<>?`,[profileId(owner),id]);await txRun(`UPDATE recovery_releases SET status='published',publish_error='',published_at=CURRENT_TIMESTAMP WHERE id=? AND profile_id=?`,[id,profileId(owner)]);await txRun(`UPDATE recovery_profiles SET current_generation=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`,[generation,profileId(owner)]);},{durability:'full',label:'publish recovery release'});}
async function addAudit(action,detail={},success=true,errorMessage='',owner=1){await run(`INSERT INTO recovery_audit_logs(profile_id,action,detail_json,success,error_message) VALUES(?,?,?,?,?)`,[profileId(owner),action,JSON.stringify(detail),success?1:0,String(errorMessage||'')]);}
function listAudit(limit=100,owner=1){return all('SELECT * FROM recovery_audit_logs WHERE profile_id=? ORDER BY id DESC LIMIT ?',[profileId(owner),Math.max(1,Math.min(500,Number(limit)||100))]);}

module.exports={initializeRecoveryTables,listProfiles,getProfile,createProfile,getSettings,updateSettings,saveKeyState,listDomains,getDomain,createDomain,updateDomain,deleteDomain,saveProbeResult,listBootstrapGroups,getBootstrapGroup,listBootstrapGroupDomains,createBootstrapGroup,deleteBootstrapGroup,listBootstrapRecords,getBootstrapRecord,createBootstrapRecord,updateBootstrapRecord,deleteBootstrapRecord,saveBootstrapPublishResult,listResolvers,getResolver,listDnsProviders,getDnsProvider,listDnsChannels,getDnsChannel,getDnsChannelByCredentialKey,createDnsChannel,updateDnsChannel,saveDnsChannelTestResult,countDnsChannelReferences,deleteDnsChannel,assignDnsChannelToLegacyCloudflare,listLookupRoutes,createLookupRoute,deleteLookupRoute,nextGeneration,createRelease,getRelease,getReleaseByGeneration,listReleases,getLatestPublishedRelease,markRelease,publishReleaseAtomically,addAudit,listAudit};
