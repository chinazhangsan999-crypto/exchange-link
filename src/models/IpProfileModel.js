'use strict';

const { run, all } = require('../config/database');

const PROFILE_COLUMNS = `profile.lookup_status AS ip_lookup_status,
  profile.network_type AS ip_network_type,
  profile.country_code AS ip_country_code,
  profile.country_name AS ip_country_name,
  profile.region AS ip_region,
  profile.city AS ip_city,
  profile.asn AS ip_asn,
  profile.asn_org AS ip_asn_org,
  profile.isp AS ip_isp,
  profile.is_hosting AS ip_is_hosting,
  profile.is_mobile AS ip_is_mobile,
  profile.is_proxy AS ip_is_proxy,
  profile.is_vpn AS ip_is_vpn,
  profile.is_tor AS ip_is_tor,
  profile.is_anycast AS ip_is_anycast,
  profile.confidence AS ip_confidence,
  profile.updated_at AS ip_profile_updated_at`;

async function initializeIpProfileTable() {
  await run(`CREATE TABLE IF NOT EXISTS ip_profiles (
    ip_key TEXT PRIMARY KEY,
    ip_version INTEGER,
    lookup_status TEXT NOT NULL DEFAULT 'pending',
    network_type TEXT NOT NULL DEFAULT 'unknown',
    country_code TEXT,
    country_name TEXT,
    region TEXT,
    city TEXT,
    asn INTEGER,
    asn_org TEXT,
    isp TEXT,
    is_hosting INTEGER,
    is_mobile INTEGER,
    is_proxy INTEGER,
    is_vpn INTEGER,
    is_tor INTEGER,
    is_anycast INTEGER,
    confidence TEXT NOT NULL DEFAULT 'unknown',
    source_version TEXT,
    last_error TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`, [], { priority: 'maintenance', label: 'create ip profiles table' });
  await run('CREATE INDEX IF NOT EXISTS idx_ip_profiles_due ON ip_profiles(lookup_status, next_retry_at, expires_at)', [], {
    priority: 'maintenance', label: 'index ip profiles due'
  });
}

async function enqueue(ipKey) {
  const value = String(ipKey || '').trim().slice(0, 128);
  if (!value) return { skipped: true };
  return run(`INSERT INTO ip_profiles(ip_key) VALUES (?)
    ON CONFLICT(ip_key) DO UPDATE SET
      lookup_status = CASE
        WHEN ip_profiles.expires_at IS NOT NULL AND ip_profiles.expires_at <= CURRENT_TIMESTAMP THEN 'pending'
        ELSE ip_profiles.lookup_status
      END,
      next_retry_at = CASE
        WHEN ip_profiles.expires_at IS NOT NULL AND ip_profiles.expires_at <= CURRENT_TIMESTAMP THEN CURRENT_TIMESTAMP
        ELSE ip_profiles.next_retry_at
      END`, [value], { priority: 'traffic', label: 'queue ip profile', durability: 'normal' });
}

async function enqueueExistingLogIps() {
  return run(`INSERT OR IGNORE INTO ip_profiles(ip_key)
    SELECT client_ip FROM inbound_logs WHERE TRIM(COALESCE(client_ip, '')) <> ''
    UNION
    SELECT client_ip FROM inbound_rejection_logs WHERE TRIM(COALESCE(client_ip, '')) <> ''`, [], {
    priority: 'maintenance', label: 'backfill ip profiles', durability: 'normal'
  });
}

async function listDue(limit = 100) {
  const safeLimit = Math.max(1, Math.min(100, Number(limit) || 100));
  return all(`SELECT ip_key, failure_count FROM ip_profiles
    WHERE (lookup_status = 'pending' AND next_retry_at <= CURRENT_TIMESTAMP)
       OR (lookup_status = 'resolved' AND expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP)
    ORDER BY CASE WHEN lookup_status = 'pending' THEN 0 ELSE 1 END, next_retry_at ASC
    LIMIT ?`, [safeLimit]);
}

const triState = value => value === null || value === undefined ? null : (value ? 1 : 0);

async function saveResolved(ipKey, result, sourceVersion = '') {
  return run(`UPDATE ip_profiles SET
      ip_version = ?, lookup_status = 'resolved', network_type = ?,
      country_code = ?, country_name = ?, region = ?, city = ?, asn = ?, asn_org = ?, isp = ?,
      is_hosting = ?, is_mobile = ?, is_proxy = ?, is_vpn = ?, is_tor = ?, is_anycast = ?,
      confidence = ?, source_version = ?, last_error = NULL, failure_count = 0,
      next_retry_at = datetime('now', '+30 days'), expires_at = datetime('now', '+30 days'),
      updated_at = CURRENT_TIMESTAMP
    WHERE ip_key = ?`, [
    Number(result.ip_version) || null,
    String(result.network_type || 'unknown').slice(0, 32),
    String(result.country_code || '').slice(0, 8) || null,
    String(result.country_name || '').slice(0, 100) || null,
    String(result.region || '').slice(0, 120) || null,
    String(result.city || '').slice(0, 120) || null,
    Number.isSafeInteger(Number(result.asn)) ? Number(result.asn) : null,
    String(result.asn_org || '').slice(0, 200) || null,
    String(result.isp || '').slice(0, 200) || null,
    triState(result.is_hosting), triState(result.is_mobile), triState(result.is_proxy),
    triState(result.is_vpn), triState(result.is_tor), triState(result.is_anycast),
    String(result.confidence || 'unknown').slice(0, 16),
    String(sourceVersion || '').slice(0, 200) || null,
    ipKey
  ], { priority: 'maintenance', label: 'save ip profile', durability: 'normal' });
}

async function saveInvalid(ipKey, message = '') {
  return run(`UPDATE ip_profiles SET lookup_status = 'invalid', network_type = 'unknown',
      last_error = ?, failure_count = 0, expires_at = datetime('now', '+30 days'),
      next_retry_at = datetime('now', '+30 days'), updated_at = CURRENT_TIMESTAMP
    WHERE ip_key = ?`, [String(message || 'IP 格式无效').slice(0, 300), ipKey], {
    priority: 'maintenance', label: 'save invalid ip profile', durability: 'normal'
  });
}

async function saveFailure(ipKey, message, failureCount) {
  const count = Math.max(1, Number(failureCount) || 1);
  const retrySeconds = [60, 300, 1800, 7200, 21600][Math.min(count - 1, 4)];
  return run(`UPDATE ip_profiles SET lookup_status = 'pending', last_error = ?,
      failure_count = ?, next_retry_at = datetime('now', ?), updated_at = CURRENT_TIMESTAMP
    WHERE ip_key = ?`, [String(message || '中心查询暂不可用').slice(0, 300), count, `+${retrySeconds} seconds`, ipKey], {
    priority: 'maintenance', label: 'defer ip profile lookup', durability: 'normal'
  });
}

module.exports = {
  PROFILE_COLUMNS,
  initializeIpProfileTable,
  enqueue,
  enqueueExistingLogIps,
  listDue,
  saveResolved,
  saveInvalid,
  saveFailure
};
