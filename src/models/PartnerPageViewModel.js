'use strict';

const { run, get, withTransaction } = require('../config/database');

const DELETE_BATCH_SIZE = 5000;

async function initializePartnerPageViewTable() {
  await run(`CREATE TABLE IF NOT EXISTS partner_session_page_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    partner_id INTEGER NOT NULL,
    visit_hash TEXT NOT NULL,
    page_kind TEXT NOT NULL CHECK(page_kind IN ('entry', 'page')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_partner_session_page_views_partner_created
    ON partner_session_page_views(partner_id, created_at)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_partner_session_page_views_visit_created
    ON partner_session_page_views(visit_hash, created_at)`);
}

async function insertBatch(items) {
  if (!Array.isArray(items) || items.length === 0) return { rows: 0 };
  return withTransaction(async transaction => {
    for (const item of items) {
      await transaction.run(`INSERT INTO partner_session_page_views(
        partner_id, visit_hash, page_kind, created_at
      ) VALUES (?, ?, ?, ?)`, [item.partnerId, item.visitHash, item.pageKind, item.createdAt]);
    }
    return { rows: items.length };
  }, { priority: 'traffic', label: 'flush partner page views', durability: 'normal' });
}

async function getRecentSummary(partnerId) {
  return get(`SELECT
      COUNT(*) AS page_pv,
      COALESCE(SUM(CASE WHEN page_kind = 'page' THEN 1 ELSE 0 END), 0) AS post_entry_page_pv,
      COUNT(DISTINCT visit_hash) AS attributed_sessions,
      COUNT(DISTINCT CASE WHEN page_kind = 'page' THEN visit_hash END) AS continued_sessions
    FROM partner_session_page_views
    WHERE partner_id = ? AND created_at >= datetime('now', '-24 hours')`, [partnerId]);
}

async function cleanupOlderThan(cutoff) {
  let deleted = 0;
  while (true) {
    const result = await run(`DELETE FROM partner_session_page_views
      WHERE id IN (
        SELECT id FROM partner_session_page_views WHERE created_at < ? LIMIT ${DELETE_BATCH_SIZE}
      )`, [cutoff], { priority: 'maintenance', label: 'cleanup partner page views' });
    if (!result.changes) break;
    deleted += result.changes;
    await new Promise(resolve => setImmediate(resolve));
  }
  return { deleted, cutoff };
}

module.exports = { initializePartnerPageViewTable, insertBatch, getRecentSummary, cleanupOlderThan };
