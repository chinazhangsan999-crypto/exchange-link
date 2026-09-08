const { run, get, all, withTransaction } = require('../config/database');
const { getLocalDayUtcRange } = require('../utils/time');

const LOG_RETENTION_DAYS = 7;
const LOG_DELETE_BATCH_SIZE = 5000;
const LOG_DELETE_YIELD_MS = 500;
const LOG_CLEANUP_TARGETS = [
  { table: 'inbound_logs', timestampColumn: 'created_at', retentionDays: LOG_RETENTION_DAYS },
  { table: 'inflow_events', timestampColumn: 'timestamp', retentionDays: LOG_RETENTION_DAYS },
  { table: 'outbound_logs', timestampColumn: 'created_at', retentionDays: LOG_RETENTION_DAYS },
  { table: 'webhook_delivery_logs', timestampColumn: 'created_at', retentionDays: 30 }
];

const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

async function cleanupTableInBatches(target, cutoff) {
  let deleted = 0;
  let batches = 0;

  while (true) {
    // 表名和时间列仅来自上方固定白名单，不能由外部输入控制。
    const result = await run(`DELETE FROM ${target.table}
      WHERE id IN (
        SELECT id FROM ${target.table}
        WHERE ${target.timestampColumn} < ?
        LIMIT ${LOG_DELETE_BATCH_SIZE}
      )`, [cutoff], { priority: 'maintenance', label: `cleanup ${target.table}` });

    if (!result.changes) break;
    deleted += result.changes;
    batches += 1;

    // 主动让出事件循环和 SQLite 写锁窗口，优先服务前台实时请求。
    await delay(LOG_DELETE_YIELD_MS);
  }

  return { deleted, batches, cutoff };
}

async function cleanupOldLogs() {
  const results = [];

  // 串行清理各事实表，避免多个批量 DELETE 同时争抢 SQLite 写锁。
  for (const target of LOG_CLEANUP_TARGETS) {
    try {
      const cutoff = new Date(Date.now() - target.retentionDays * 24 * 60 * 60 * 1000)
        .toISOString().slice(0, 19).replace('T', ' ');
      const value = await cleanupTableInBatches(target, cutoff);
      results.push({ table: target.table, status: 'fulfilled', value });
    } catch (reason) {
      results.push({ table: target.table, status: 'rejected', reason });
    }
  }

  return results;
}

async function createClaimToken({ tokenHash, partnerId, ip, ttlSeconds, startedAtMs, referer }) {
  return withTransaction(async transaction => {
    await transaction.run("DELETE FROM inflow_claim_tokens WHERE expires_at < datetime('now')");
    return transaction.run("INSERT INTO inflow_claim_tokens(token_hash, partner_id, ip, expires_at, started_at_ms, referer) VALUES (?, ?, ?, datetime('now', ?), ?, ?)", [tokenHash, partnerId, ip, `+${ttlSeconds} seconds`, startedAtMs, referer || '']);
  }, { priority: 'traffic', label: 'create inflow claim' });
}

async function getValidClaimTokenHash(tokenHash) {
  return get("SELECT token_hash FROM inflow_claim_tokens WHERE token_hash = ? AND claimed_at IS NULL AND expires_at >= datetime('now')", [tokenHash]);
}

async function getActiveClaim(tokenHash) {
  return get("SELECT * FROM inflow_claim_tokens WHERE token_hash = ? AND claimed_at IS NULL AND expires_at >= datetime('now')", [tokenHash]);
}

async function processTrackPing({ tokenHash, claim, clientIp, userAgent, visitId }) {
  return withTransaction(async transaction => {
    const consume = await transaction.run("UPDATE inflow_claim_tokens SET claimed_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND claimed_at IS NULL", [tokenHash]);
    if (!consume.changes) return { alreadyUsed: true, newlyCounted: false, autoApproved: false };

    const duplicated = await transaction.get("SELECT id FROM inbound_logs WHERE link_id = ? AND client_ip = ? AND created_at >= datetime('now', '-24 hours') LIMIT 1", [claim.partner_id, clientIp]);
    // 每次通过验证的真实心跳都是一条 PV 事实；计分和自动审核仍使用 DISTINCT IP 去重。
    await transaction.run("INSERT INTO inbound_logs(link_id, client_ip, user_agent, referer, visit_id, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))", [claim.partner_id, clientIp, userAgent, claim.referer || '', visitId]);

    let autoApproved = false;
    const pending = await transaction.get('SELECT is_approved FROM partners WHERE id = ?', [claim.partner_id]);
    if (pending?.is_approved === 0) {
      const thresholdConfig = await transaction.get("SELECT value FROM site_configs WHERE key = 'auto_approve_threshold'");
      const threshold = Math.max(1, Number.parseInt(thresholdConfig?.value, 10) || 10);
      const history = await transaction.get('SELECT COUNT(DISTINCT client_ip) AS uv FROM inbound_logs WHERE link_id = ?', [claim.partner_id]);
      if (Number(history.uv) >= threshold) {
        const approval = await transaction.run('UPDATE partners SET is_approved = 1 WHERE id = ? AND is_approved = 0', [claim.partner_id]);
        autoApproved = approval.changes > 0;
      }
    }
    return { alreadyUsed: false, newlyCounted: !duplicated, autoApproved };
  }, { priority: 'traffic', label: 'record inbound ping' });
}

async function recordOutbound(linkId, clientIp, attribution = {}) {
  const sourcePartnerId = Number.isSafeInteger(Number(attribution.sourcePartnerId)) ? Number(attribution.sourcePartnerId) : null;
  const visitId = typeof attribution.visitId === 'string' && attribution.visitId.length <= 128 ? attribution.visitId : null;
  return withTransaction(async transaction => {
    await transaction.run("INSERT INTO outbound_logs(link_id, client_ip, source_partner_id, visit_id, created_at) VALUES (?, ?, ?, ?, datetime('now'))", [linkId, clientIp, sourcePartnerId, visitId]);
  }, { priority: 'traffic', label: 'record outbound click' });
}

async function getOverviewTraffic() {
  return get("SELECT COUNT(DISTINCT client_ip) AS value FROM inbound_logs WHERE created_at >= datetime('now', '-24 hours')");
}

async function getTodayExchange(now = new Date()) {
  const { start, end } = getLocalDayUtcRange(now);
  const [inbound, outbound] = await Promise.all([
    get('SELECT COUNT(DISTINCT client_ip) AS count FROM inbound_logs WHERE created_at >= ? AND created_at < ?', [start, end]),
    get('SELECT COUNT(DISTINCT client_ip) AS count FROM outbound_logs WHERE created_at >= ? AND created_at < ?', [start, end])
  ]);
  return { inbound, outbound };
}

async function getNewPartnerTraffic() {
  const [last24h, last7d] = await Promise.all([
    get("SELECT COUNT(DISTINCT l.client_ip) AS value FROM inbound_logs l JOIN partners p ON p.id = l.link_id WHERE p.created_at >= datetime('now', '-24 hours') AND l.created_at >= datetime('now', '-24 hours')"),
    get("SELECT COUNT(DISTINCT l.client_ip) AS value FROM inbound_logs l INNER JOIN partners p ON p.id = l.link_id WHERE p.created_at >= datetime('now', '-7 days') AND l.created_at >= datetime('now', '-7 days')")
  ]);
  return { last24h, last7d };
}

async function listRiskPartnerMetrics() {
  return all(`SELECT p.id, p.name, p.domain,
    COALESCE((SELECT COUNT(*) FROM outbound_logs o WHERE o.link_id = p.id), 0) AS outflow_clicks,
    COUNT(DISTINCT l.client_ip) AS score_24h,
    COUNT(l.id) AS pv_24h,
    COALESCE((SELECT MAX(ip_count) FROM (
      SELECT COUNT(*) AS ip_count
      FROM inbound_logs i2
      WHERE i2.link_id = p.id AND i2.created_at >= datetime('now', '-24 hours')
      GROUP BY i2.client_ip
    )), 0) AS top_ip_requests
    FROM partners p
    LEFT JOIN inbound_logs l ON l.link_id = p.id AND l.created_at >= datetime('now', '-24 hours')
    WHERE p.is_approved = 1 AND COALESCE(p.is_whitelisted, 0) = 0
    GROUP BY p.id`);
}

async function clearPartnerTraffic(partnerId) {
  return withTransaction(async transaction => {
    const inbound = await transaction.run('DELETE FROM inbound_logs WHERE link_id = ?', [partnerId]);
    const outbound = await transaction.run('DELETE FROM outbound_logs WHERE link_id = ?', [partnerId]);
    const attributedOutbound = await transaction.run('DELETE FROM outbound_logs WHERE source_partner_id = ?', [partnerId]);
    const claims = await transaction.run('DELETE FROM inflow_claim_tokens WHERE partner_id = ?', [partnerId]);
    return {
      inbound: inbound.changes,
      outbound: outbound.changes + attributedOutbound.changes,
      claims: claims.changes
    };
  }, { priority: 'interactive', label: 'clear partner traffic' });
}

async function getPartnerAnalytics(partnerId) {
  const [summary, inflowLogs, requestRows, deadWaterInteraction, attributedInteraction, hourlyPeak] = await Promise.all([
    get(`SELECT COUNT(*) AS pv,
      COUNT(DISTINCT client_ip) AS uv,
      CASE WHEN COUNT(*) > 0 THEN 100 ELSE 0 END AS compliance_rate,
      SUM(CASE WHEN referer IS NULL OR TRIM(referer) = '' THEN 1 ELSE 0 END) AS empty_referer_count
      FROM inbound_logs
      WHERE link_id = ? AND created_at >= datetime('now', '-24 hours')`, [partnerId]),
    all(`SELECT ip, user_agent, referer, timestamp FROM (
      SELECT client_ip AS ip, user_agent, referer, created_at AS timestamp,
        ROW_NUMBER() OVER (PARTITION BY client_ip ORDER BY created_at DESC, id DESC) AS row_number
      FROM inbound_logs
      WHERE link_id = ? AND created_at >= datetime('now', '-24 hours')
    ) WHERE row_number = 1 ORDER BY timestamp DESC LIMIT 100`, [partnerId]),
    all("SELECT client_ip AS ip, COUNT(*) AS requests, MAX(created_at) AS last_seen FROM inbound_logs WHERE link_id = ? AND created_at >= datetime('now', '-24 hours') GROUP BY client_ip", [partnerId]),
    // 近 24 小时的死水观察指标：同一入站 IP 后续是否有任何出站行为。
    // 它仅用于人工审核信号，不能证明点击一定来自该友链。
    get(`WITH inbound_ips AS (
      SELECT client_ip, MIN(created_at) AS first_seen
      FROM inbound_logs
      WHERE link_id = ? AND created_at >= datetime('now', '-24 hours')
      GROUP BY client_ip
    )
    SELECT COUNT(*) AS inbound_uv,
      COALESCE(SUM(CASE WHEN EXISTS (
        SELECT 1 FROM outbound_logs outbound
        WHERE outbound.client_ip = inbound_ips.client_ip
          AND outbound.created_at >= inbound_ips.first_seen
      ) THEN 1 ELSE 0 END), 0) AS interacted_uv
    FROM inbound_ips`, [partnerId]),
    // 可归因指标：同一已验证 visit_id 的 30 分钟内后续出站。
    get(`WITH inbound_visits AS (
      SELECT visit_id, MIN(created_at) AS first_seen
      FROM inbound_logs
      WHERE link_id = ? AND visit_id IS NOT NULL AND created_at >= datetime('now', '-24 hours')
      GROUP BY visit_id
    )
    SELECT COUNT(*) AS attributed_inbound_visits,
      COALESCE(SUM(CASE WHEN EXISTS (
        SELECT 1 FROM outbound_logs outbound
        WHERE outbound.source_partner_id = ?
          AND outbound.visit_id = inbound_visits.visit_id
          AND outbound.created_at >= inbound_visits.first_seen
          AND outbound.created_at < datetime(inbound_visits.first_seen, '+30 minutes')
      ) THEN 1 ELSE 0 END), 0) AS interacted_visits
    FROM inbound_visits`, [partnerId, partnerId]),
    get(`SELECT COALESCE(MAX(hourly_uv), 0) AS peak_hourly_uv
      FROM (
        SELECT COUNT(DISTINCT client_ip) AS hourly_uv
        FROM inbound_logs
        WHERE link_id = ? AND created_at >= datetime('now', '-24 hours')
        GROUP BY strftime('%Y-%m-%d %H', created_at)
      )`, [partnerId])
  ]);
  return { summary, inflowLogs, requestRows, deadWaterInteraction, attributedInteraction, hourlyPeak };
}

async function searchInboundLogs(query = '') {
  const keyword = String(query || '').trim();
  return all(`SELECT l.id, l.link_id AS partner_id, l.client_ip AS ip, l.user_agent,
    l.created_at AS timestamp, p.name AS partner_name, p.domain
    FROM inbound_logs l
    JOIN partners p ON p.id = l.link_id
    ${keyword ? 'WHERE l.client_ip LIKE ? OR p.name LIKE ? OR p.domain LIKE ?' : ''}
    ORDER BY l.created_at DESC
    LIMIT 200`, keyword ? [`%${keyword}%`, `%${keyword}%`, `%${keyword}%`] : []);
}

module.exports = {
  LOG_RETENTION_DAYS,
  cleanupOldLogs,
  createClaimToken,
  getValidClaimTokenHash,
  getActiveClaim,
  processTrackPing,
  recordOutbound,
  getOverviewTraffic,
  getTodayExchange,
  getNewPartnerTraffic,
  listRiskPartnerMetrics,
  clearPartnerTraffic,
  getPartnerAnalytics,
  searchInboundLogs
};
