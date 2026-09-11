'use strict';

const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const ip = String(process.argv[2] || '').trim();
if (!ip) {
  console.error('用法：node scripts/audit-inflow-ip.js <IP>');
  process.exit(1);
}

const databasePath = path.resolve(process.env.DB_PATH || path.join(__dirname, '..', 'webring.db'));
const database = new sqlite3.Database(databasePath, sqlite3.OPEN_READONLY);
database.configure('busyTimeout', 5000);
const all = (sql, params = []) => new Promise((resolve, reject) => {
  database.all(sql, params, (error, rows) => (error ? reject(error) : resolve(rows)));
});

(async () => {
  const [validRows, rejectedRows, scoreRows] = await Promise.all([
    all(`SELECT l.id, l.link_id, p.name AS partner_name, p.domain, l.client_ip,
      l.referer, l.observed_domain, l.attribution_method, l.visit_id, l.attempt_id,
      l.source_token_id, l.created_at
      FROM inbound_logs l LEFT JOIN partners p ON p.id = l.link_id
      WHERE l.client_ip = ? ORDER BY l.created_at DESC, l.id DESC`, [ip]),
    all(`SELECT r.id, r.partner_id, p.name AS partner_name, p.domain, r.client_ip,
      r.visitor_type, r.stage, r.reason_code, r.reason_text, r.referer,
      r.observed_domain, r.attribution_method, r.occurrence_count, r.attempt_id,
      CASE WHEN r.reason_code = 'entry_cooldown' THEN 'suppressed' ELSE r.classification END AS effective_classification,
      CASE WHEN r.reason_code = 'entry_cooldown' AND EXISTS (
        SELECT 1 FROM inbound_logs valid WHERE valid.link_id = r.partner_id
          AND valid.client_ip = r.client_ip
          AND valid.created_at >= datetime(r.first_seen_at, '-1 minute')
          AND valid.created_at <= datetime(r.last_seen_at, '+2 minutes')
      ) THEN 'resolved_by_valid_visit' ELSE r.resolution_status END AS effective_resolution_status,
      r.classification AS stored_classification, r.resolution_status AS stored_resolution_status,
      r.resolved_at, r.resolved_visit_id,
      r.first_seen_at, r.last_seen_at
      FROM inbound_rejection_logs r LEFT JOIN partners p ON p.id = r.partner_id
      WHERE r.client_ip = ? ORDER BY r.last_seen_at DESC, r.id DESC`, [ip]),
    all(`SELECT p.id AS partner_id, p.name AS partner_name, p.domain,
      COUNT(l.id) AS ip_pv_24h, COUNT(DISTINCT l.client_ip) AS partner_uv_24h,
      MIN(l.created_at) AS first_ip_visit_24h, MAX(l.created_at) AS last_ip_visit_24h
      FROM inbound_logs l JOIN partners p ON p.id = l.link_id
      WHERE l.client_ip = ? AND l.created_at >= datetime('now', '-24 hours')
      GROUP BY p.id, p.name, p.domain`, [ip])
  ]);
  console.log(JSON.stringify({ checkedAtUtc: new Date().toISOString(), databasePath, ip, validRows, rejectedRows, scoreRows }, null, 2));
})()
  .catch(error => {
    console.error(error.stack || error);
    process.exitCode = 1;
  })
  .finally(() => database.close());
