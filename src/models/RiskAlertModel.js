'use strict';

const { run, withTransaction } = require('../config/database');

/** Stores only partner-level risk state, never visitor IPs or UA details. */
async function shouldNotify(partnerId, fingerprint) {
  return withTransaction(async ({ get: txGet, run: txRun }) => {
    const previous = await txGet(
      'SELECT fingerprint, resolved_at FROM risk_alert_states WHERE partner_id = ?',
      [partnerId]
    );
    const changed = !previous || previous.resolved_at || previous.fingerprint !== fingerprint;
    if (!changed) return { notify: false, reason: 'unchanged' };

    await txRun(`INSERT INTO risk_alert_states(partner_id, fingerprint, first_detected_at, last_alerted_at, resolved_at)
      VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL)
      ON CONFLICT(partner_id) DO UPDATE SET
        fingerprint = excluded.fingerprint,
        last_alerted_at = CURRENT_TIMESTAMP,
        resolved_at = NULL`, [partnerId, fingerprint]);
    return { notify: true, reason: previous?.resolved_at ? 'reappeared' : (previous ? 'changed' : 'new') };
  });
}

async function resolveInactive(activePartnerIds) {
  const ids = [...new Set((activePartnerIds || []).map(Number).filter(Number.isInteger))];
  if (!ids.length) return run('UPDATE risk_alert_states SET resolved_at = CURRENT_TIMESTAMP WHERE resolved_at IS NULL');
  const placeholders = ids.map(() => '?').join(', ');
  return run(`UPDATE risk_alert_states SET resolved_at = CURRENT_TIMESTAMP
    WHERE resolved_at IS NULL AND partner_id NOT IN (${placeholders})`, ids);
}

module.exports = { shouldNotify, resolveInactive };
