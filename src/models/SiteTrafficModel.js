'use strict';

const { run, get, all, withTransaction } = require('../config/database');

const DELETE_BATCH_SIZE = 5000;

async function initializeSiteTrafficTable() {
  await run(`CREATE TABLE IF NOT EXISTS site_visit_hourly (
    bucket_start TEXT NOT NULL,
    visitor_hash TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    pv_count INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (bucket_start, visitor_hash, ip_hash)
  )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_site_visit_hourly_bucket
    ON site_visit_hourly(bucket_start)`);
}

async function upsertHourlyBatch(items) {
  if (!Array.isArray(items) || items.length === 0) return { rows: 0, pv: 0 };
  return withTransaction(async transaction => {
    let pv = 0;
    for (const item of items) {
      const count = Math.max(1, Number(item.pvCount) || 1);
      await transaction.run(`INSERT INTO site_visit_hourly(
        bucket_start, visitor_hash, ip_hash, pv_count, first_seen_at, last_seen_at
      ) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(bucket_start, visitor_hash, ip_hash) DO UPDATE SET
        pv_count = site_visit_hourly.pv_count + excluded.pv_count,
        first_seen_at = MIN(site_visit_hourly.first_seen_at, excluded.first_seen_at),
        last_seen_at = MAX(site_visit_hourly.last_seen_at, excluded.last_seen_at)`, [
        item.bucketStart, item.visitorHash, item.ipHash, count, item.firstSeenAt, item.lastSeenAt
      ]);
      pv += count;
    }
    return { rows: items.length, pv };
  }, { priority: 'traffic', label: 'flush site traffic batch', durability: 'normal' });
}

async function getSummaryBetween(start, end) {
  return get(`SELECT
      COUNT(DISTINCT ip_hash) AS total_ip,
      COUNT(DISTINCT visitor_hash) AS total_uv,
      COALESCE(SUM(pv_count), 0) AS total_pv
    FROM site_visit_hourly
    WHERE bucket_start >= ? AND bucket_start < ?`, [start, end]);
}

async function getHourlyBetween(start, end) {
  return all(`SELECT bucket_start,
      COUNT(DISTINCT ip_hash) AS total_ip,
      COUNT(DISTINCT visitor_hash) AS total_uv,
      COALESCE(SUM(pv_count), 0) AS total_pv
    FROM site_visit_hourly
    WHERE bucket_start >= ? AND bucket_start < ?
    GROUP BY bucket_start
    ORDER BY bucket_start ASC`, [start, end]);
}

async function getRolling24HourSamples(samples) {
  if (!Array.isArray(samples) || samples.length === 0) return [];
  const values = samples.map(() => '(?, ?)').join(', ');
  const params = samples.flatMap((sample, index) => [index, sample.end]);
  return all(`WITH samples(sample_index, sample_end) AS (VALUES ${values})
    SELECT samples.sample_index,
      COUNT(DISTINCT visits.ip_hash) AS total_ip,
      COUNT(DISTINCT visits.visitor_hash) AS total_uv,
      COALESCE(SUM(visits.pv_count), 0) AS total_pv
    FROM samples
    LEFT JOIN site_visit_hourly visits
      ON visits.bucket_start >= datetime(samples.sample_end, '-24 hours')
      AND visits.bucket_start < samples.sample_end
    GROUP BY samples.sample_index
    ORDER BY samples.sample_index ASC`, params);
}

async function getDailyBetween(start, end) {
  return all(`SELECT strftime('%Y-%m-%d', datetime(bucket_start, '+8 hours')) AS local_day,
      COUNT(DISTINCT ip_hash) AS total_ip,
      COUNT(DISTINCT visitor_hash) AS total_uv,
      COALESCE(SUM(pv_count), 0) AS total_pv
    FROM site_visit_hourly
    WHERE bucket_start >= ? AND bucket_start < ?
    GROUP BY local_day
    ORDER BY local_day ASC`, [start, end]);
}

async function cleanupOlderThan(cutoff) {
  let deleted = 0;
  let batches = 0;
  while (true) {
    const result = await run(`DELETE FROM site_visit_hourly
      WHERE rowid IN (
        SELECT rowid FROM site_visit_hourly WHERE bucket_start < ? LIMIT ${DELETE_BATCH_SIZE}
      )`, [cutoff], { priority: 'maintenance', label: 'cleanup site traffic' });
    if (!result.changes) break;
    deleted += result.changes;
    batches += 1;
    await new Promise(resolve => setImmediate(resolve));
  }
  return { deleted, batches, cutoff };
}

module.exports = {
  initializeSiteTrafficTable,
  upsertHourlyBatch,
  getSummaryBetween,
  getHourlyBetween,
  getRolling24HourSamples,
  getDailyBetween,
  cleanupOlderThan
};
