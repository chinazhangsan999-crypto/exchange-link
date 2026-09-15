const { run, get, all, withTransaction } = require('../config/database');
const { getLocalDayUtcRange } = require('../utils/time');
const { PROFILE_COLUMNS } = require('./IpProfileModel');

const LOG_RETENTION_DAYS = 7;
const LOG_DELETE_BATCH_SIZE = 5000;
const LOG_DELETE_YIELD_MS = 500;
const LOG_CLEANUP_TARGETS = [
  { table: 'inbound_logs', timestampColumn: 'created_at', retentionDays: LOG_RETENTION_DAYS },
  { table: 'inbound_rejection_logs', timestampColumn: 'last_seen_at', retentionDays: LOG_RETENTION_DAYS },
  { table: 'inflow_events', timestampColumn: 'timestamp', retentionDays: LOG_RETENTION_DAYS },
  { table: 'outbound_logs', timestampColumn: 'created_at', retentionDays: LOG_RETENTION_DAYS },
  { table: 'ad_runtime_events', timestampColumn: 'created_at', retentionDays: LOG_RETENTION_DAYS },
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

  // 未完成心跳的访问只在定时维护阶段归档，避免给正常访客的入站请求增加批量写入。
  try {
    const value = await archiveExpiredClaims();
    results.push({ table: 'inflow_claim_tokens', status: 'fulfilled', value });
  } catch (reason) {
    results.push({ table: 'inflow_claim_tokens', status: 'rejected', reason });
  }

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

async function archiveExpiredClaims() {
  return withTransaction(async transaction => {
    const archived = await transaction.run(`INSERT INTO inbound_rejection_logs(
      client_ip, visitor_hash, user_agent, referer, observed_domain, partner_id,
      source_token_id, attribution_method, visitor_type, stage, reason_code, reason_text,
      request_path, attempt_id, classification, first_seen_at, last_seen_at, created_at
    ) SELECT ip, visitor_hash, user_agent, COALESCE(referer, ''), COALESCE(observed_domain, ''), partner_id,
      source_token_id, COALESCE(attribution_method, ''), 'source_validation', 'heartbeat',
      'heartbeat_expired', '15分钟内未完成有效心跳', COALESCE(request_path, '/'),
      COALESCE(attempt_id, ''), 'rejected', created_at, expires_at, expires_at
      FROM inflow_claim_tokens
      WHERE claimed_at IS NULL AND expires_at < datetime('now')`);
    const removed = await transaction.run("DELETE FROM inflow_claim_tokens WHERE expires_at < datetime('now')");
    return { archived: archived.changes || 0, removed: removed.changes || 0 };
  }, { priority: 'maintenance', label: 'archive expired inflow claims', durability: 'normal' });
}

async function createClaimToken({
  tokenHash,
  partnerId,
  ip,
  ttlSeconds,
  startedAtMs,
  referer,
  sourceTokenId = null,
  sidPartnerId = null,
  domainPartnerId = null,
  attributionMethod = 'domain_only',
  observedDomain = '',
  userAgent = '',
  visitorHash = '',
  requestPath = '/',
  attemptId = ''
}) {
  return withTransaction(async transaction => {
    return transaction.run(`INSERT INTO inflow_claim_tokens(
      token_hash, partner_id, ip, expires_at, started_at_ms, referer,
      source_token_id, sid_partner_id, domain_partner_id, attribution_method, observed_domain,
      user_agent, visitor_hash, request_path, attempt_id
    ) VALUES (?, ?, ?, datetime('now', ?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
      tokenHash,
      partnerId,
      ip,
      `+${ttlSeconds} seconds`,
      startedAtMs,
      referer || '',
      sourceTokenId,
      sidPartnerId,
      domainPartnerId,
      String(attributionMethod || 'domain_only').slice(0, 64),
      String(observedDomain || '').slice(0, 253),
      String(userAgent || '').slice(0, 500),
      String(visitorHash || '').slice(0, 64),
      String(requestPath || '/').slice(0, 500),
      String(attemptId || '').slice(0, 64)
    ]);
  }, { priority: 'traffic', label: 'create inflow claim', durability: 'normal' });
}

async function recordRejectedInbound(event = {}) {
  const clientIp = String(event.clientIp || '').trim().slice(0, 128);
  const stage = String(event.stage || 'source').trim().slice(0, 64);
  const reasonCode = String(event.reasonCode || 'unknown').trim().slice(0, 64);
  if (!clientIp || !stage || !reasonCode) return { skipped: true };
  const partnerId = Number.isInteger(Number(event.partnerId)) && Number(event.partnerId) > 0
    ? Number(event.partnerId) : null;
  const values = {
    visitorHash: String(event.visitorHash || '').slice(0, 64),
    userAgent: String(event.userAgent || '').replace(/[\r\n\t]+/g, ' ').slice(0, 500),
    referer: String(event.referer || '').replace(/[\r\n\t]+/g, ' ').slice(0, 2048),
    observedDomain: String(event.observedDomain || '').slice(0, 253),
    sourceTokenId: Number.isInteger(Number(event.sourceTokenId)) && Number(event.sourceTokenId) > 0
      ? Number(event.sourceTokenId) : null,
    attributionMethod: String(event.attributionMethod || '').slice(0, 64),
    visitorType: String(event.visitorType || 'source_validation').slice(0, 64),
    reasonText: String(event.reasonText || '未通过入站校验').replace(/[\r\n\t]+/g, ' ').slice(0, 300),
    requestPath: String(event.requestPath || '/').slice(0, 500),
    attemptId: String(event.attemptId || '').slice(0, 64),
    classification: event.classification === 'suppressed' ? 'suppressed' : 'rejected'
  };
  return withTransaction(async transaction => {
    const existing = await transaction.get(`SELECT id FROM inbound_rejection_logs
      WHERE ((? <> '' AND visitor_hash = ?) OR (? = '' AND client_ip = ?))
        AND stage = ? AND reason_code = ?
        AND COALESCE(partner_id, 0) = COALESCE(?, 0)
        AND last_seen_at >= datetime('now', '-10 minutes')
      ORDER BY last_seen_at DESC LIMIT 1`, [
      values.visitorHash, values.visitorHash, values.visitorHash, clientIp, stage, reasonCode, partnerId
    ]);
    if (existing) {
      return transaction.run(`UPDATE inbound_rejection_logs
        SET occurrence_count = occurrence_count + 1, last_seen_at = CURRENT_TIMESTAMP,
          client_ip = ?, user_agent = ?, referer = ?, observed_domain = ?, reason_text = ?,
          attempt_id = ?, classification = ?, resolution_status = 'unresolved',
          resolved_at = NULL, resolved_visit_id = NULL
        WHERE id = ?`, [clientIp, values.userAgent, values.referer, values.observedDomain,
        values.reasonText, values.attemptId, values.classification, existing.id]);
    }
    return transaction.run(`INSERT INTO inbound_rejection_logs(
      client_ip, visitor_hash, user_agent, referer, observed_domain, partner_id,
      source_token_id, attribution_method, visitor_type, stage, reason_code, reason_text,
      request_path, attempt_id, classification
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
      clientIp, values.visitorHash, values.userAgent, values.referer, values.observedDomain,
      partnerId, values.sourceTokenId, values.attributionMethod, values.visitorType,
      stage, reasonCode, values.reasonText, values.requestPath, values.attemptId, values.classification
    ]);
  }, { priority: 'traffic', label: 'record rejected inbound', durability: 'normal' });
}

async function getValidClaimTokenHash(tokenHash) {
  return get("SELECT token_hash FROM inflow_claim_tokens WHERE token_hash = ? AND claimed_at IS NULL AND expires_at >= datetime('now')", [tokenHash]);
}

async function getActiveClaim(tokenHash) {
  return get("SELECT * FROM inflow_claim_tokens WHERE token_hash = ? AND claimed_at IS NULL AND expires_at >= datetime('now')", [tokenHash]);
}

async function processTrackPing({
  tokenHash,
  claim,
  clientIp,
  userAgent,
  visitId,
  visitorHash = '',
  clientFingerprint = '',
  screenResolution = '',
  clientLanguage = '',
  clientPlatform = ''
}) {
  return withTransaction(async transaction => {
    const consume = await transaction.run("UPDATE inflow_claim_tokens SET claimed_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND claimed_at IS NULL", [tokenHash]);
    if (!consume.changes) return { alreadyUsed: true, newlyCounted: false, autoApproved: false };

    const duplicated = await transaction.get("SELECT id FROM inbound_logs WHERE link_id = ? AND client_ip = ? AND created_at >= datetime('now', '-24 hours') LIMIT 1", [claim.partner_id, clientIp]);
    // 每次通过验证的真实心跳都是一条 PV 事实；计分和自动审核仍使用 DISTINCT IP 去重。
    await transaction.run(`INSERT INTO inbound_logs(
      link_id, client_ip, user_agent, referer, visit_id,
      source_token_id, sid_partner_id, domain_partner_id, attribution_method, observed_domain,
      visitor_hash, client_fingerprint, screen_resolution, client_language, client_platform, attempt_id,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`, [
      claim.partner_id,
      clientIp,
      userAgent,
      claim.referer || '',
      visitId,
      claim.source_token_id || null,
      claim.sid_partner_id || null,
      claim.domain_partner_id || null,
      String(claim.attribution_method || 'domain_only').slice(0, 64),
      String(claim.observed_domain || '').slice(0, 253),
      String(visitorHash || claim.visitor_hash || '').slice(0, 64),
      String(clientFingerprint || '').slice(0, 64),
      String(screenResolution || '').slice(0, 32),
      String(clientLanguage || '').slice(0, 32),
      String(clientPlatform || '').slice(0, 80),
      String(claim.attempt_id || '').slice(0, 64)
    ]);

    // 入口冷却只是抑制同一访客的重复页面请求；如果已有凭证随后成功，保留审计记录但标记为已解决。
    await transaction.run(`UPDATE inbound_rejection_logs
      SET resolution_status = 'resolved_by_valid_visit', resolved_at = CURRENT_TIMESTAMP,
        resolved_visit_id = ?
      WHERE partner_id = ? AND client_ip = ? AND reason_code = 'entry_cooldown'
        AND classification = 'suppressed' AND resolution_status = 'unresolved'
        AND last_seen_at >= datetime('now', '-2 minutes')`, [visitId, claim.partner_id, clientIp]);

    // SID 使用次数只在通过滑块并完成 3 秒真实心跳后增加；无效或被放弃的落地页不计入。
    if (claim.source_token_id) {
      await transaction.run(`UPDATE partner_source_tokens
        SET used_count = used_count + 1, last_used_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 1`, [claim.source_token_id]);
    }

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
  }, { priority: 'traffic', label: 'record inbound ping', durability: 'normal' });
}

async function recordOutbound(linkId, clientIp, attribution = {}) {
  const sourcePartnerId = Number.isSafeInteger(Number(attribution.sourcePartnerId)) ? Number(attribution.sourcePartnerId) : null;
  const visitId = typeof attribution.visitId === 'string' && attribution.visitId.length <= 128 ? attribution.visitId : null;
  return withTransaction(async transaction => {
    await transaction.run("INSERT INTO outbound_logs(link_id, client_ip, source_partner_id, visit_id, created_at) VALUES (?, ?, ?, ?, datetime('now'))", [linkId, clientIp, sourcePartnerId, visitId]);
  }, { priority: 'traffic', label: 'record outbound click', durability: 'normal' });
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

async function getTodayTrafficLeader(now = new Date()) {
  const { start, end } = getLocalDayUtcRange(now);
  return get(`SELECT p.id, p.name, p.domain, p.url, COUNT(DISTINCT l.client_ip) AS uv
    FROM inbound_logs l
    INNER JOIN partners p ON p.id = l.link_id
    WHERE l.created_at >= ? AND l.created_at < ?
      AND p.is_approved = 1 AND COALESCE(p.is_internal, 0) = 0
    GROUP BY p.id
    ORDER BY uv DESC, p.priority DESC, p.id ASC
    LIMIT 1`, [start, end]);
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

async function getPartnerAnalytics(partnerId, { includeClients = true, clientEventLimit = 2000 } = {}) {
  const safeClientEventLimit = Math.max(100, Math.min(5000, Number(clientEventLimit) || 2000));
  const [summary, inflowLogs, requestRows, deadWaterInteraction, attributedInteraction, hourlyPeak, partnerPageViews, partnerPageViewVisits, clientEvents, clientInteractions] = await Promise.all([
    get(`SELECT COUNT(*) AS pv,
      COUNT(DISTINCT client_ip) AS uv,
      CASE WHEN COUNT(*) > 0 THEN 100 ELSE 0 END AS compliance_rate,
      SUM(CASE WHEN (referer IS NULL OR TRIM(referer) = '')
        AND COALESCE(attribution_method, '') <> 'sid_fallback_no_referer'
        THEN 1 ELSE 0 END) AS empty_referer_count,
      SUM(CASE WHEN referer IS NULL OR TRIM(referer) = '' THEN 1 ELSE 0 END) AS raw_empty_referer_count,
      SUM(CASE WHEN COALESCE(attribution_method, '') = 'sid_fallback_no_referer'
        THEN 1 ELSE 0 END) AS sid_no_referer_count
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
      )`, [partnerId]),
    get(`SELECT
        COUNT(*) AS page_pv,
        COALESCE(SUM(CASE WHEN page_kind = 'page' THEN 1 ELSE 0 END), 0) AS post_entry_page_pv,
        COUNT(DISTINCT visit_hash) AS attributed_sessions,
        COUNT(DISTINCT CASE WHEN page_kind = 'page' THEN visit_hash END) AS continued_sessions
      FROM partner_session_page_views
      WHERE partner_id = ? AND created_at >= datetime('now', '-24 hours')`, [partnerId]),
    all(`SELECT visit_hash,
        COALESCE(SUM(CASE WHEN page_kind = 'page' THEN 1 ELSE 0 END), 0) AS post_entry_page_pv
      FROM partner_session_page_views
      WHERE partner_id = ? AND created_at >= datetime('now', '-24 hours')
      GROUP BY visit_hash`, [partnerId]),
    includeClients
      ? all(`SELECT inbound.id, inbound.client_ip AS ip, inbound.user_agent, inbound.referer,
          inbound.visit_id, inbound.attribution_method, inbound.observed_domain,
          inbound.visitor_hash, inbound.client_fingerprint, inbound.screen_resolution,
          inbound.client_language, inbound.client_platform, inbound.created_at AS timestamp,
          ${PROFILE_COLUMNS}
        FROM inbound_logs inbound
        LEFT JOIN ip_profiles profile ON profile.ip_key = inbound.client_ip
        WHERE inbound.link_id = ? AND inbound.created_at >= datetime('now', '-24 hours')
        ORDER BY inbound.created_at DESC, inbound.id DESC
        LIMIT ?`, [partnerId, safeClientEventLimit])
      : Promise.resolve([]),
    includeClients
      ? all(`SELECT inbound.visit_id, COUNT(outbound.id) AS click_count,
          MIN(MAX(0, ROUND((julianday(outbound.created_at) - julianday(inbound.created_at)) * 86400))) AS first_interaction_seconds
        FROM inbound_logs inbound
        INNER JOIN outbound_logs outbound
          ON outbound.source_partner_id = inbound.link_id
          AND outbound.visit_id = inbound.visit_id
          AND outbound.created_at >= inbound.created_at
          AND outbound.created_at < datetime(inbound.created_at, '+30 minutes')
        WHERE inbound.link_id = ? AND inbound.visit_id IS NOT NULL
          AND inbound.created_at >= datetime('now', '-24 hours')
        GROUP BY inbound.visit_id`, [partnerId])
      : Promise.resolve([])
  ]);
  return {
    summary,
    inflowLogs,
    requestRows,
    deadWaterInteraction,
    attributedInteraction,
    hourlyPeak,
    partnerPageViews,
    partnerPageViewVisits,
    clientEvents,
    clientInteractions,
    clientEventsTruncated: includeClients && Number(summary.pv || 0) > clientEvents.length
  };
}

function normalizePagination(page, pageSize = 100) {
  const safePage = Math.max(1, Number.parseInt(page, 10) || 1);
  const safePageSize = Math.max(1, Math.min(100, Number.parseInt(pageSize, 10) || 100));
  return { page: safePage, pageSize: safePageSize, offset: (safePage - 1) * safePageSize };
}

function paginationResult(items, total, page, pageSize) {
  const totalItems = Math.max(0, Number(total) || 0);
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const safePage = Math.min(page, totalPages);
  return {
    items,
    pagination: {
      page: safePage,
      pageSize,
      total: totalItems,
      totalPages,
      from: totalItems ? (safePage - 1) * pageSize + 1 : 0,
      to: totalItems ? Math.min(safePage * pageSize, totalItems) : 0,
      hasPrevious: safePage > 1,
      hasNext: safePage < totalPages
    }
  };
}

async function searchInboundLogs(query = '', { page = 1, pageSize = 100 } = {}) {
  const keyword = String(query || '').trim();
  const paging = normalizePagination(page, pageSize);
  const whereSql = keyword ? 'WHERE l.client_ip LIKE ? OR p.name LIKE ? OR p.domain LIKE ?' : '';
  const filterParams = keyword ? [`%${keyword}%`, `%${keyword}%`, `%${keyword}%`] : [];
  const totalRow = await get(`SELECT COUNT(*) AS total
    FROM inbound_logs l
    JOIN partners p ON p.id = l.link_id
    ${whereSql}`, filterParams);
  const total = Number(totalRow?.total || 0);
  const totalPages = Math.max(1, Math.ceil(total / paging.pageSize));
  const effectivePage = Math.min(paging.page, totalPages);
  const offset = (effectivePage - 1) * paging.pageSize;
  const items = await all(`SELECT l.id, l.link_id AS partner_id, l.client_ip AS ip, l.user_agent,
    l.referer, l.observed_domain, l.attribution_method, l.created_at AS timestamp,
    p.name AS partner_name, p.domain, ${PROFILE_COLUMNS},
    CASE WHEN EXISTS (
      SELECT 1 FROM inbound_logs previous
      WHERE previous.link_id = l.link_id AND previous.client_ip = l.client_ip
        AND previous.created_at >= datetime(l.created_at, '-24 hours')
        AND (previous.created_at < l.created_at OR (previous.created_at = l.created_at AND previous.id < l.id))
    ) THEN 0 ELSE 1 END AS newly_counted
    FROM inbound_logs l
    JOIN partners p ON p.id = l.link_id
    LEFT JOIN ip_profiles profile ON profile.ip_key = l.client_ip
    ${whereSql}
    ORDER BY l.created_at DESC, l.id DESC
    LIMIT ? OFFSET ?`, [...filterParams, paging.pageSize, offset]);
  return paginationResult(items, total, effectivePage, paging.pageSize);
}

async function searchRejectedInboundLogs(query = '', { page = 1, pageSize = 100 } = {}) {
  const keyword = String(query || '').trim();
  const paging = normalizePagination(page, pageSize);
  const whereSql = keyword ? `WHERE r.client_ip LIKE ? OR COALESCE(p.name, '') LIKE ? OR COALESCE(p.domain, '') LIKE ?
      OR r.observed_domain LIKE ? OR r.reason_text LIKE ? OR r.classification LIKE ? OR r.resolution_status LIKE ?` : '';
  const filterParams = keyword ? Array(7).fill(`%${keyword}%`) : [];
  const totalRow = await get(`SELECT COUNT(*) AS total
    FROM inbound_rejection_logs r
    LEFT JOIN partners p ON p.id = r.partner_id
    ${whereSql}`, filterParams);
  const total = Number(totalRow?.total || 0);
  const totalPages = Math.max(1, Math.ceil(total / paging.pageSize));
  const effectivePage = Math.min(paging.page, totalPages);
  const offset = (effectivePage - 1) * paging.pageSize;
  const items = await all(`SELECT r.id, r.client_ip AS ip, r.user_agent, r.referer, r.observed_domain,
    r.partner_id, r.source_token_id, r.attribution_method, r.visitor_type,
    r.stage, r.reason_code, r.reason_text, r.request_path, r.occurrence_count,
    r.attempt_id,
    CASE WHEN r.reason_code = 'entry_cooldown' THEN 'suppressed' ELSE r.classification END AS classification,
    CASE WHEN r.reason_code = 'entry_cooldown' AND EXISTS (
      SELECT 1 FROM inbound_logs valid
      WHERE valid.link_id = r.partner_id AND valid.client_ip = r.client_ip
        AND valid.created_at >= datetime(r.first_seen_at, '-1 minute')
        AND valid.created_at <= datetime(r.last_seen_at, '+2 minutes')
    ) THEN 'resolved_by_valid_visit' ELSE r.resolution_status END AS resolution_status,
    COALESCE(r.resolved_at, (
      SELECT MIN(valid.created_at) FROM inbound_logs valid
      WHERE valid.link_id = r.partner_id AND valid.client_ip = r.client_ip
        AND valid.created_at >= datetime(r.first_seen_at, '-1 minute')
        AND valid.created_at <= datetime(r.last_seen_at, '+2 minutes')
    )) AS resolved_at,
    COALESCE(r.resolved_visit_id, (
      SELECT valid.visit_id FROM inbound_logs valid
      WHERE valid.link_id = r.partner_id AND valid.client_ip = r.client_ip
        AND valid.created_at >= datetime(r.first_seen_at, '-1 minute')
        AND valid.created_at <= datetime(r.last_seen_at, '+2 minutes')
      ORDER BY valid.created_at ASC, valid.id ASC LIMIT 1
    )) AS resolved_visit_id,
    r.first_seen_at, r.last_seen_at AS timestamp, p.name AS partner_name, p.domain,
    ${PROFILE_COLUMNS}
    FROM inbound_rejection_logs r
    LEFT JOIN partners p ON p.id = r.partner_id
    LEFT JOIN ip_profiles profile ON profile.ip_key = r.client_ip
    ${whereSql}
    ORDER BY r.last_seen_at DESC, r.id DESC
    LIMIT ? OFFSET ?`, [...filterParams, paging.pageSize, offset]);
  return paginationResult(items, total, effectivePage, paging.pageSize);
}

module.exports = {
  LOG_RETENTION_DAYS,
  cleanupOldLogs,
  archiveExpiredClaims,
  createClaimToken,
  recordRejectedInbound,
  getValidClaimTokenHash,
  getActiveClaim,
  processTrackPing,
  recordOutbound,
  getOverviewTraffic,
  getTodayExchange,
  getTodayTrafficLeader,
  getNewPartnerTraffic,
  listRiskPartnerMetrics,
  clearPartnerTraffic,
  getPartnerAnalytics,
  searchInboundLogs,
  searchRejectedInboundLogs
};
