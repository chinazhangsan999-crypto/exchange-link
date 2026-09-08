const { run, get, all, withTransaction } = require('../config/database');
const { insertPartnerSid } = require('./SourceTokenModel');

function assertTaskWriteAllowed(options = {}) {
  if (!options.signal?.aborted || options.allowAbortedWrite === true) return;
  const error = options.signal.reason instanceof Error ? options.signal.reason : new Error('后台任务已取消');
  if (!error.code) error.code = 'TASK_ABORTED';
  throw error;
}

const TRAFFIC_JOINS = `LEFT JOIN (
    SELECT link_id, COUNT(DISTINCT client_ip) AS score_24h
    FROM inbound_logs
    WHERE created_at >= datetime('now', '-24 hours')
    GROUP BY link_id
  ) recent ON recent.link_id = p.id
  LEFT JOIN (
    SELECT link_id, COUNT(DISTINCT client_ip) AS total_score
    FROM inbound_logs
    GROUP BY link_id
  ) inbound_total ON inbound_total.link_id = p.id
  LEFT JOIN (
    SELECT link_id, COUNT(*) AS outflow_clicks
    FROM outbound_logs
    GROUP BY link_id
  ) outbound_total ON outbound_total.link_id = p.id
  LEFT JOIN (
    SELECT link_id, COUNT(DISTINCT client_ip) AS outflow_24h
    FROM outbound_logs
    WHERE created_at >= datetime('now', '-24 hours')
    GROUP BY link_id
  ) outbound_recent ON outbound_recent.link_id = p.id`;

// 公开接口严格使用字段白名单，禁止 contact/backlink/巡检字段从 Model 泄露。
const PUBLIC_LINK_QUERY = `SELECT
  p.id, p.name, p.domain, p.url, p.category, p.description, p.priority,
  COALESCE(recent.score_24h, 0) AS score_24h
  FROM partners p
  LEFT JOIN (
    SELECT link_id, COUNT(DISTINCT client_ip) AS score_24h
    FROM inbound_logs
    WHERE created_at >= datetime('now', '-24 hours')
    GROUP BY link_id
  ) recent ON recent.link_id = p.id`;

const ADMIN_LINK_QUERY = `SELECT
  p.id, p.name, p.domain, p.url, p.category, p.description, p.contact,
  (SELECT token.sid FROM partner_source_tokens token
    WHERE token.default_partner_id = p.id AND token.status = 1
    ORDER BY token.id DESC LIMIT 1) AS source_sid,
  p.priority,
  p.is_approved, p.is_whitelisted, p.is_exempt, p.backlink_status, p.backlink_url, p.last_checked_at,
  p.failed_check_count, p.failed_check_count AS check_fail_count,
  p.lost_count, p.ping_exempt, p.ping_failed_count, p.ping_status,
  p.last_ping_at, p.created_at,
  COALESCE(recent.score_24h, 0) AS score_24h,
  COALESCE(inbound_total.total_score, 0) AS total_score,
  COALESCE(outbound_total.outflow_clicks, 0) AS outflow_clicks,
  ROUND(1.0 * COALESCE(outbound_total.outflow_clicks, 0) / (COALESCE(recent.score_24h, 0) + 1), 3) AS roi,
  COALESCE(outbound_recent.outflow_24h, 0) AS outflow_24h
  FROM partners p
  ${TRAFFIC_JOINS}`;

const finishPublicLinkQuery = where => `${PUBLIC_LINK_QUERY} ${where || ''}`;
const finishAdminLinkQuery = where => `${ADMIN_LINK_QUERY} ${where || ''}`;
const VISIBLE_FILTER = "p.is_approved = 1 AND COALESCE(p.backlink_status, 'valid') <> 'lost' AND COALESCE(p.ping_status, 'ok') = 'ok'";

async function listInflowCandidates({ includeUrl = false } = {}) {
  return all(includeUrl
    ? 'SELECT id, name, domain, url FROM partners WHERE is_approved IN (0, 1)'
    : 'SELECT id, domain FROM partners WHERE is_approved IN (0, 1)');
}

async function listPingTargets() {
  return all(`SELECT id, name, domain, url, ping_exempt, ping_status, ping_failed_count, last_ping_at
    FROM partners
    WHERE is_approved = 1
      AND COALESCE(is_internal, 0) = 0
      AND COALESCE(ping_exempt, 0) = 0
      AND COALESCE(ping_failed_count, 0) <= 30
    ORDER BY id ASC`);
}

async function listDeepPingRevivalTargets() {
  return all(`SELECT id, name, domain, url, ping_exempt, ping_status, ping_failed_count, last_ping_at
    FROM partners
    WHERE is_approved = 1
      AND COALESCE(is_internal, 0) = 0
      AND COALESCE(ping_exempt, 0) = 0
      AND COALESCE(ping_failed_count, 0) > 30
    ORDER BY id ASC`);
}

async function recordPingFailure(id, failedCount, status, options = {}) {
  assertTaskWriteAllowed(options);
  return run("UPDATE partners SET ping_failed_count = ?, ping_status = ?, last_ping_at = datetime('now') WHERE id = ?", [failedCount, status, id], { priority: 'background', label: 'record ping failure' });
}

async function recordPingSuccess(id, options = {}) {
  assertTaskWriteAllowed(options);
  return run("UPDATE partners SET ping_failed_count = 0, ping_status = 'ok', last_ping_at = datetime('now') WHERE id = ?", [id], { priority: 'background', label: 'record ping success' });
}

async function touchPingTimestamp(id, options = {}) {
  assertTaskWriteAllowed(options);
  return run("UPDATE partners SET last_ping_at = datetime('now') WHERE id = ?", [id], { priority: 'background', label: 'touch ping timestamp' });
}

async function listBacklinkInspectionTargets() {
  return all(`SELECT p.id, p.name, p.url, p.backlink_url, p.backlink_status, p.is_exempt,
    p.failed_check_count, p.lost_count, COALESCE(recent.rolling_ips, 0) AS traffic_24h
    FROM partners p
    LEFT JOIN (
      SELECT link_id, COUNT(DISTINCT client_ip) AS rolling_ips
      FROM inbound_logs
      WHERE created_at >= datetime('now', '-24 hours')
      GROUP BY link_id
    ) recent ON recent.link_id = p.id
    WHERE p.is_approved = 1
      AND COALESCE(p.is_internal, 0) = 0
      AND COALESCE(p.is_exempt, 0) = 0
      AND NOT (
        COALESCE(p.failed_check_count, 0) > 15
        AND COALESCE(p.backlink_status, '') = 'dead'
      )
    ORDER BY p.id ASC`);
}

async function listDeepBacklinkRevivalTargets() {
  return all(`SELECT p.id, p.name, p.url, p.backlink_url, p.backlink_status, p.is_exempt,
    p.failed_check_count, p.lost_count, COALESCE(recent.rolling_ips, 0) AS traffic_24h
    FROM partners p
    LEFT JOIN (
      SELECT link_id, COUNT(DISTINCT client_ip) AS rolling_ips
      FROM inbound_logs
      WHERE created_at >= datetime('now', '-24 hours')
      GROUP BY link_id
    ) recent ON recent.link_id = p.id
    WHERE p.is_approved = 1
      AND COALESCE(p.is_internal, 0) = 0
      AND COALESCE(p.is_exempt, 0) = 0
      AND COALESCE(p.failed_check_count, 0) > 15
      AND COALESCE(p.backlink_status, '') = 'dead'
    ORDER BY p.id ASC`);
}

async function recordBacklinkLost(id, options = {}) {
  assertTaskWriteAllowed(options);
  return run("UPDATE partners SET backlink_status = 'lost', failed_check_count = 0, lost_count = lost_count + 1, last_checked_at = datetime('now') WHERE id = ?", [id], { priority: 'background', label: 'record backlink lost' });
}

async function recordBacklinkStatus(id, status, backlinkUrl = null, options = {}) {
  assertTaskWriteAllowed(options);
  if (backlinkUrl) {
    return run("UPDATE partners SET backlink_url = ?, backlink_status = ?, failed_check_count = 0, last_checked_at = datetime('now') WHERE id = ?", [backlinkUrl, status, id], { priority: 'background', label: 'record backlink status' });
  }
  return run("UPDATE partners SET backlink_status = ?, failed_check_count = 0, last_checked_at = datetime('now') WHERE id = ?", [status, id], { priority: 'background', label: 'record backlink status' });
}

async function touchBacklinkCheck(id, options = {}) {
  assertTaskWriteAllowed(options);
  return run("UPDATE partners SET last_checked_at = datetime('now') WHERE id = ?", [id], { priority: 'background', label: 'touch backlink check' });
}

async function recordBacklinkFailure(id, status, failedCount, options = {}) {
  assertTaskWriteAllowed(options);
  return run("UPDATE partners SET backlink_status = ?, failed_check_count = ?, last_checked_at = datetime('now') WHERE id = ?", [status, failedCount, id], { priority: 'background', label: 'record backlink failure' });
}

async function markTrafficExempt(id, options = {}) {
  assertTaskWriteAllowed(options);
  return run("UPDATE partners SET backlink_status = 'valid', failed_check_count = 0, last_checked_at = datetime('now') WHERE id = ?", [id], { priority: 'background', label: 'mark traffic exempt' });
}

async function getPublicLists() {
  const [hotList, links] = await Promise.all([
    // 官方内部节点可零流量进入榜单，但 score_24h 始终保持数据库真实聚合值。
    all(`${finishPublicLinkQuery(`WHERE ${VISIBLE_FILTER} AND (COALESCE(recent.score_24h, 0) > 0 OR p.priority = 999)`)}
      ORDER BY p.priority DESC, score_24h DESC, p.id ASC LIMIT 10`),
    all(`${finishPublicLinkQuery(`WHERE ${VISIBLE_FILTER}`)} ORDER BY p.priority DESC, score_24h DESC, p.id ASC`)
  ]);
  return { hotList, links };
}

async function getPublicDetail(id) {
  return get(finishPublicLinkQuery(`WHERE ${VISIBLE_FILTER} AND p.id = ?`), [id]);
}

async function getRecommendations(id, category) {
  return all(`${finishPublicLinkQuery(`WHERE ${VISIBLE_FILTER} AND p.id <> ?`)}
    ORDER BY CASE WHEN p.category = ? THEN 0 ELSE 1 END, p.priority DESC, score_24h DESC, p.id ASC
    LIMIT 12`, [id, category]);
}

async function getApprovedOutboundTarget(id) {
  return get('SELECT id, url FROM partners WHERE id = ? AND is_approved = 1', [id]);
}

async function getOverviewPartnerStats() {
  const [active, leader, clicks] = await Promise.all([
    get('SELECT COUNT(*) AS value FROM partners WHERE is_approved = 1'),
    get(`${finishPublicLinkQuery('WHERE p.is_approved = 1')} ORDER BY score_24h DESC, p.id ASC LIMIT 1`),
    get(`SELECT COUNT(*) AS value FROM outbound_logs o
      INNER JOIN partners p ON p.id = o.link_id
      WHERE p.is_approved = 1`)
  ]);
  return { active, leader, clicks };
}

async function getNewPartnerCounts() {
  const [last24h, last7d] = await Promise.all([
    get("SELECT COUNT(*) AS value FROM partners WHERE created_at >= datetime('now', '-24 hours')"),
    get("SELECT COUNT(*) AS value FROM partners WHERE created_at >= datetime('now', '-7 days')")
  ]);
  return { last24h, last7d };
}

async function listReviewPartners() {
  return all(`SELECT p.id, p.name, p.url, p.category, p.description, p.contact, p.created_at, p.is_approved,
    COUNT(DISTINCT CASE WHEN l.created_at >= datetime('now', '-24 hours') THEN l.client_ip END) AS score_24h,
    COUNT(DISTINCT l.client_ip) AS total_uv
    FROM partners p
    LEFT JOIN inbound_logs l ON l.link_id = p.id
    WHERE p.is_approved = 0
    GROUP BY p.id
    ORDER BY p.created_at ASC`);
}

async function listAdminPartners(query = '') {
  const keyword = String(query || '').trim();
  const rows = await all(
    `${finishAdminLinkQuery(keyword ? 'WHERE p.name LIKE ? OR p.domain LIKE ? OR p.category LIKE ?' : '')}
     ORDER BY p.priority DESC, score_24h DESC, p.id ASC`,
    keyword ? [`%${keyword}%`, `%${keyword}%`, `%${keyword}%`] : []
  );
  rows.forEach(row => { row.score_total = row.total_score; });
  return rows;
}

async function findAnalyticsPartner(id) {
  return get(`SELECT p.id, p.name, p.domain, p.is_approved, p.is_whitelisted, p.priority,
    COALESCE((SELECT COUNT(*) FROM outbound_logs o WHERE o.link_id = p.id), 0) AS outflow_clicks
    FROM partners p WHERE p.id = ?`, [id]);
}

async function createPendingPartner({ name, domain, url, description, contact, category }) {
  return withTransaction(async transaction => {
    const result = await transaction.run(`INSERT INTO partners(name, domain, url, description, contact, category, is_approved, backlink_status)
      VALUES (?, ?, ?, ?, ?, ?, 0, 'pending')`, [name, domain, url, description, contact, category]);
    const token = await insertPartnerSid(transaction, result.id);
    return { ...result, sourceSid: token.sid };
  }, { priority: 'interactive', label: 'create pending partner', durability: 'full' });
}

async function createApprovedPartner({ name, domain, url, category, backlinkUrl, contact, description, isExempt = 0, pingExempt = 0 }) {
  const exempt = Number(isExempt) === 1 ? 1 : 0;
  const connectionExempt = Number(pingExempt) === 1 ? 1 : 0;
  return withTransaction(async transaction => {
    const result = await transaction.run(`INSERT INTO partners(name, domain, url, category, backlink_url, contact, description, is_approved, is_exempt, ping_exempt, backlink_status)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`, [name, domain, url, category, backlinkUrl, contact, description, exempt, connectionExempt, exempt ? 'valid' : 'pending']);
    const token = await insertPartnerSid(transaction, result.id);
    return { ...result, sourceSid: token.sid };
  }, { priority: 'interactive', label: 'create approved partner', durability: 'full' });
}

async function updatePartner(id, changes) {
  const allowed = ['name', 'category', 'description', 'contact', 'url', 'domain', 'backlink_url', 'priority', 'is_exempt', 'ping_exempt'];
  const fields = [];
  const values = [];
  for (const key of allowed) {
    if (!Object.prototype.hasOwnProperty.call(changes, key)) continue;
    fields.push(`${key} = ?`);
    values.push(changes[key]);
  }
  if (Number(changes.is_exempt) === 1) {
    fields.push("backlink_status = 'valid'", 'failed_check_count = 0');
  }
  if (Number(changes.ping_exempt) === 1) {
    fields.push("ping_status = 'ok'", 'ping_failed_count = 0');
  }
  if (!fields.length) return { changes: 0, empty: true };
  values.push(id);
  return run(`UPDATE partners SET ${fields.join(', ')} WHERE id = ?`, values);
}

async function updateApproval(id, status) {
  return run('UPDATE partners SET is_approved = ? WHERE id = ?', [status, id]);
}

async function whitelistPartner(id) {
  return run('UPDATE partners SET is_whitelisted = 1 WHERE id = ?', [id]);
}

async function deletePartner(id) {
  return withTransaction(async transaction => {
    await transaction.run(`UPDATE partner_source_tokens
      SET status = 0, revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
      WHERE default_partner_id = ? AND status = 1`, [id]);
    return transaction.run('DELETE FROM partners WHERE id = ?', [id]);
  }, { priority: 'interactive', label: 'delete partner and revoke sid', durability: 'full' });
}

async function findBacklinkPartner(id) {
  return get('SELECT id, name, url, backlink_status, backlink_url, is_exempt, failed_check_count, lost_count FROM partners WHERE id = ?', [id]);
}

async function findPingPartner(id) {
  return get(`SELECT id, name, url, ping_exempt, ping_status, ping_failed_count, last_ping_at
    FROM partners WHERE id = ? AND is_approved = 1`, [id]);
}

async function resetLostCount(id) {
  return run('UPDATE partners SET lost_count = 0 WHERE id = ?', [id]);
}

async function resetCheckStatus(id) {
  return run(`UPDATE partners
    SET failed_check_count = 0,
        backlink_status = 'pending',
        last_checked_at = NULL,
        ping_failed_count = 0,
        ping_status = 'ok',
        last_ping_at = NULL
    WHERE id = ?`, [id]);
}

/** CSV 为增量控制源：按规范化主域名更新或新增，但绝不删除人工申请的数据。 */
async function syncPartnersFromCsv(items) {
  return withTransaction(async ({ run: txRun, get: txGet }) => {
    let inserted = 0;
    let updated = 0;
    for (const item of items) {
      // CSV 是分类的运营配置源；首次出现的新分类一并写入，避免友链分类成为孤立值。
      await txRun(`INSERT OR IGNORE INTO categories(name, sort_order)
        VALUES (?, COALESCE((SELECT MAX(sort_order) + 1 FROM categories), 0))`, [item.category]);
      // 兼容历史上保存过子域名的记录；更新时会将它们收敛为主域名。
      const existing = await txGet(`SELECT id FROM partners
        WHERE lower(domain) = lower(?) OR lower(domain) LIKE lower(?)
        ORDER BY CASE WHEN lower(domain) = lower(?) THEN 0 ELSE 1 END, id ASC
        LIMIT 1`, [item.domain, `%.${item.domain}`, item.domain]);
      if (existing) {
        await txRun(`UPDATE partners
          SET name = ?, url = ?, domain = ?, category = ?, contact = ?, backlink_url = ?,
              description = ?, priority = ?, is_approved = ?
          WHERE id = ?`, [
          item.name, item.url, item.domain, item.category, item.contact, item.backlinkUrl,
          item.description, item.priority, item.status, existing.id
        ]);
        await insertPartnerSid({ run: txRun, get: txGet }, existing.id);
        updated += 1;
      } else {
        const result = await txRun(`INSERT INTO partners(
            name, domain, url, category, contact, backlink_url, description,
            priority, is_approved, backlink_status
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`, [
          item.name, item.domain, item.url, item.category, item.contact,
          item.backlinkUrl, item.description, item.priority, item.status
        ]);
        await insertPartnerSid({ run: txRun, get: txGet }, result.id);
        inserted += 1;
      }
    }
    return { inserted, updated, total: items.length };
  }, { priority: 'background', label: 'sync partners from csv', maxWaitMs: 120000, durability: 'full' });
}

function listPartnersForExport() {
  return all(`SELECT name, url, category, contact, backlink_url, description,
      priority, is_approved
    FROM partners
    ORDER BY priority DESC, id ASC`);
}

module.exports = {
  listInflowCandidates,
  listPingTargets,
  listDeepPingRevivalTargets,
  recordPingFailure,
  recordPingSuccess,
  touchPingTimestamp,
  listBacklinkInspectionTargets,
  listDeepBacklinkRevivalTargets,
  recordBacklinkLost,
  recordBacklinkStatus,
  touchBacklinkCheck,
  recordBacklinkFailure,
  markTrafficExempt,
  getPublicLists,
  getPublicDetail,
  getRecommendations,
  getApprovedOutboundTarget,
  getOverviewPartnerStats,
  getNewPartnerCounts,
  listReviewPartners,
  listAdminPartners,
  findAnalyticsPartner,
  createPendingPartner,
  createApprovedPartner,
  updatePartner,
  updateApproval,
  whitelistPartner,
  deletePartner,
  findBacklinkPartner,
  findPingPartner,
  resetLostCount,
  resetCheckStatus,
  syncPartnersFromCsv,
  listPartnersForExport
};
