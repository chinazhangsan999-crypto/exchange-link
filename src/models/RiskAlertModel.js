'use strict';

const { run, get, withTransaction } = require('../config/database');

const FAILURE_RETRY_COOLDOWN_MS = 5 * 60 * 1000;

function sqliteUtcToMs(value) {
  if (!value) return 0;
  const date = new Date(`${String(value).replace(' ', 'T').replace(/Z$/, '')}Z`);
  return Number.isNaN(date.getTime()) ? 0 : date.getTime();
}

/** 只判断是否需要投递，绝不在投递前标记“已告警”。 */
async function getNotificationDecision(partnerId, fingerprint) {
  const previous = await get(`SELECT fingerprint, last_alerted_at, last_alerted_fingerprint, last_failed_at, resolved_at
    FROM risk_alert_states WHERE partner_id = ?`, [partnerId]);
  const changed = !previous || previous.resolved_at || previous.fingerprint !== fingerprint;
  if (!changed && previous.last_alerted_at && previous.last_alerted_fingerprint === fingerprint) return { notify: false, reason: 'unchanged' };
  if (!changed && previous.last_failed_at
    && Date.now() - sqliteUtcToMs(previous.last_failed_at) < FAILURE_RETRY_COOLDOWN_MS) {
    return { notify: false, reason: 'failure_cooldown' };
  }
  return { notify: true, reason: changed ? (previous?.resolved_at ? 'reappeared' : (previous ? 'changed' : 'new')) : 'retry_after_failure' };
}

/** 首次启用时只登记存量风险，避免历史记录一次性刷屏。 */
async function baselineRiskState(partnerId, fingerprint) {
  return run(`INSERT INTO risk_alert_states(partner_id, fingerprint, first_detected_at, last_alerted_at, last_alerted_fingerprint, resolved_at)
    VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, NULL)
    ON CONFLICT(partner_id) DO UPDATE SET
      fingerprint = excluded.fingerprint,
      last_alerted_at = CURRENT_TIMESTAMP,
      last_alerted_fingerprint = excluded.last_alerted_fingerprint,
      last_failed_at = NULL,
      last_failure_reason = NULL,
      resolved_at = NULL`, [partnerId, fingerprint, fingerprint]);
}

async function markAlertDelivered(partnerId, fingerprint) {
  return withTransaction(async ({ run: txRun }) => txRun(`INSERT INTO risk_alert_states(
    partner_id, fingerprint, first_detected_at, last_alerted_at, last_alerted_fingerprint, last_failed_at, last_failure_reason, last_attempt_at, resolved_at
  ) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, NULL, NULL, CURRENT_TIMESTAMP, NULL)
  ON CONFLICT(partner_id) DO UPDATE SET
    fingerprint = excluded.fingerprint,
    last_alerted_at = CURRENT_TIMESTAMP,
    last_alerted_fingerprint = excluded.last_alerted_fingerprint,
    last_failed_at = NULL,
    last_failure_reason = NULL,
    last_attempt_at = CURRENT_TIMESTAMP,
    resolved_at = NULL`, [partnerId, fingerprint, fingerprint]));
}

async function markAlertFailed(partnerId, fingerprint, reason) {
  const safeReason = String(reason || '投递失败').slice(0, 300);
  return withTransaction(async ({ run: txRun }) => txRun(`INSERT INTO risk_alert_states(
    partner_id, fingerprint, first_detected_at, last_alerted_at, last_alerted_fingerprint, last_failed_at, last_failure_reason, last_attempt_at, resolved_at
  ) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, NULL)
  ON CONFLICT(partner_id) DO UPDATE SET
    fingerprint = excluded.fingerprint,
    last_alerted_fingerprint = NULL,
    last_failed_at = CURRENT_TIMESTAMP,
    last_failure_reason = ?,
    last_attempt_at = CURRENT_TIMESTAMP,
    resolved_at = NULL`, [partnerId, fingerprint, safeReason, safeReason]));
}

async function resolveInactive(activePartnerIds) {
  const ids = [...new Set((activePartnerIds || []).map(Number).filter(Number.isInteger))];
  if (!ids.length) return run('UPDATE risk_alert_states SET resolved_at = CURRENT_TIMESTAMP WHERE resolved_at IS NULL');
  const placeholders = ids.map(() => '?').join(', ');
  return run(`UPDATE risk_alert_states SET resolved_at = CURRENT_TIMESTAMP
    WHERE resolved_at IS NULL AND partner_id NOT IN (${placeholders})`, ids);
}

module.exports = { getNotificationDecision, baselineRiskState, markAlertDelivered, markAlertFailed, resolveInactive };
