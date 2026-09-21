'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const { createClient } = require('redis');
const { DATABASE_URL, REDIS_URL, IS_PRODUCTION } = require('../config/env');
const DecisionService = require('./DecisionService');

let pool = null;
let redis = null;
let ready = false;

function redisKey(siteKey, visitorHash) {
  return `risk:decision:${siteKey}:${visitorHash}`;
}

async function initialize() {
  if (ready) return;
  if (DATABASE_URL) {
    pool = new Pool({ connectionString: DATABASE_URL, max: 10, idleTimeoutMillis: 30_000 });
    const migration = fs.readFileSync(path.join(__dirname, '..', '..', 'migrations', '001_initial.sql'), 'utf8');
    await pool.query(migration);
    const sequenceResult = await pool.query('SELECT COALESCE(MAX(sequence), 0) AS sequence FROM risk_decisions');
    DecisionService.setSequenceFloor(sequenceResult.rows[0]?.sequence);
  }
  if (REDIS_URL) {
    redis = createClient({ url: REDIS_URL });
    redis.on('error', error => console.error('Redis 连接错误：', error.message));
    await redis.connect();
  }
  if (IS_PRODUCTION && (!pool || !redis)) throw new Error('生产环境风险中心必须连接 PostgreSQL 与 Redis');
  ready = true;
}

async function persistBatch(events, decisions) {
  if (!pool || (!events.length && !decisions.length)) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const event of events) {
      await client.query(
        `INSERT INTO risk_events
          (event_id, site_key, visitor_hash, event_type, occurred_at, evidence)
         VALUES ($1, $2, $3, $4, to_timestamp($5 / 1000.0), $6::jsonb)
         ON CONFLICT (event_id) DO NOTHING`,
        [event.eventId, event.siteKey, event.visitorHash, event.eventType, event.occurredAt, JSON.stringify(event.evidence || {})]
      );
    }
    for (const item of decisions) {
      await client.query(
        `INSERT INTO risk_decisions
          (sequence, site_key, subject_type, subject_hash, score, decision, reasons, policy_version, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, to_timestamp($9 / 1000.0))
         ON CONFLICT (sequence) DO NOTHING`,
        [item.sequence, item.siteKey, item.subjectType, item.subjectHash, item.score, item.decision,
          JSON.stringify(item.reasons || []), item.policyVersion, item.expiresAt]
      );
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
  if (redis) {
    await Promise.all(decisions.map(item => redis.set(
      redisKey(item.siteKey, item.subjectHash),
      JSON.stringify(item),
      { PX: Math.max(1, item.expiresAt - Date.now()) }
    )));
  }
}

function normalizeDecisionRow(row) {
  if (!row) return null;
  return {
    sequence: Number(row.sequence),
    siteKey: row.site_key,
    subjectType: row.subject_type,
    subjectHash: row.subject_hash,
    score: Number(row.score),
    decision: row.decision,
    reasons: Array.isArray(row.reasons) ? row.reasons : [],
    policyVersion: row.policy_version,
    expiresAt: new Date(row.expires_at).getTime()
  };
}

async function listDelta(siteKey, cursor, limit) {
  if (!pool) return DecisionService.listDelta(siteKey, cursor, limit);
  const result = await pool.query(
    `SELECT sequence, site_key, subject_type, subject_hash, score, decision, reasons, policy_version, expires_at
       FROM risk_decisions
      WHERE site_key = $1 AND sequence > $2 AND revoked_at IS NULL AND expires_at > NOW()
      ORDER BY sequence ASC LIMIT $3`,
    [siteKey, Math.max(0, Number(cursor) || 0), Math.max(1, Math.min(1000, Number(limit) || 1000))]
  );
  const items = result.rows.map(normalizeDecisionRow);
  return { cursor: items.at(-1)?.sequence || Math.max(0, Number(cursor) || 0), items };
}

async function evaluate(siteKey, visitorHash) {
  if (redis) {
    const cached = await redis.get(redisKey(siteKey, visitorHash));
    if (cached) return JSON.parse(cached);
  }
  if (!pool) return DecisionService.evaluate(siteKey, visitorHash);
  const result = await pool.query(
    `SELECT sequence, site_key, subject_type, subject_hash, score, decision, reasons, policy_version, expires_at
       FROM risk_decisions
      WHERE site_key = $1 AND subject_hash = $2 AND revoked_at IS NULL AND expires_at > NOW()
      ORDER BY sequence DESC LIMIT 1`,
    [siteKey, visitorHash]
  );
  return normalizeDecisionRow(result.rows[0]) || DecisionService.evaluate(siteKey, visitorHash);
}

function secretHash(secret) {
  return crypto.createHash('sha256').update(String(secret || '')).digest('hex');
}

async function authorizeClient(clientId, siteKey, secret) {
  if (!pool) return { ok: true, clientId, siteKey };
  if (!/^[A-Za-z0-9_-]{3,64}$/.test(siteKey)) return { ok: false, reason: 'invalid_site' };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO sites (site_key, name) VALUES ($1, $1)
       ON CONFLICT (site_key) DO NOTHING`,
      [siteKey]
    );
    const existing = await client.query(
      'SELECT site_key FROM api_clients WHERE client_id = $1 FOR UPDATE',
      [clientId]
    );
    if (existing.rows[0] && existing.rows[0].site_key !== siteKey) {
      await client.query('ROLLBACK');
      return { ok: false, reason: 'site_mismatch' };
    }
    await client.query(
      `INSERT INTO api_clients (client_id, site_key, secret_hash, last_used_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (client_id) DO UPDATE
         SET secret_hash = EXCLUDED.secret_hash, last_used_at = NOW()
       WHERE api_clients.secret_hash <> EXCLUDED.secret_hash
          OR api_clients.last_used_at IS NULL
          OR api_clients.last_used_at < NOW() - INTERVAL '1 minute'`,
      [clientId, siteKey, secretHash(secret)]
    );
    const status = await client.query(
      `SELECT s.enabled AS site_enabled, c.enabled AS client_enabled
         FROM api_clients c JOIN sites s ON s.site_key = c.site_key
        WHERE c.client_id = $1`,
      [clientId]
    );
    await client.query('COMMIT');
    const row = status.rows[0];
    if (!row?.site_enabled) return { ok: false, reason: 'site_disabled' };
    if (!row?.client_enabled) return { ok: false, reason: 'client_disabled' };
    return { ok: true, clientId, siteKey };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function getAdminOverview() {
  if (!pool) return { sites: 0, enabledSites: 0, events24h: 0, decisions24h: 0 };
  const result = await pool.query(
    `SELECT
       (SELECT COUNT(*)::int FROM sites) AS sites,
       (SELECT COUNT(*)::int FROM sites WHERE enabled) AS enabled_sites,
       (SELECT COUNT(*)::int FROM risk_events WHERE created_at >= NOW() - INTERVAL '24 hours') AS events_24h,
       (SELECT COUNT(*)::int FROM risk_decisions WHERE created_at >= NOW() - INTERVAL '24 hours') AS decisions_24h`
  );
  const row = result.rows[0] || {};
  return {
    sites: Number(row.sites) || 0,
    enabledSites: Number(row.enabled_sites) || 0,
    events24h: Number(row.events_24h) || 0,
    decisions24h: Number(row.decisions_24h) || 0
  };
}

async function listAdminSites() {
  if (!pool) return [];
  const result = await pool.query(
    `SELECT s.site_key, s.name, s.enabled, s.created_at, s.updated_at,
            (SELECT COUNT(*)::int FROM risk_events e
              WHERE e.site_key = s.site_key AND e.created_at >= NOW() - INTERVAL '24 hours') AS events_24h,
            (SELECT COUNT(*)::int FROM risk_decisions d
              WHERE d.site_key = s.site_key AND d.created_at >= NOW() - INTERVAL '24 hours') AS decisions_24h,
            (SELECT MAX(c.last_used_at) FROM api_clients c WHERE c.site_key = s.site_key) AS last_used_at,
            COALESCE((
              SELECT jsonb_agg(jsonb_build_object('clientId', c.client_id, 'enabled', c.enabled)
                               ORDER BY c.client_id)
                FROM api_clients c WHERE c.site_key = s.site_key
            ), '[]'::jsonb) AS clients
       FROM sites s
      ORDER BY s.created_at ASC`
  );
  return result.rows.map(row => ({
    siteKey: row.site_key,
    name: row.name,
    enabled: Boolean(row.enabled),
    events24h: Number(row.events_24h) || 0,
    decisions24h: Number(row.decisions_24h) || 0,
    lastUsedAt: row.last_used_at,
    clients: row.clients || [],
    createdAt: row.created_at,
    updatedAt: row.updated_at
  }));
}

async function setSiteEnabled(siteKey, enabled, actor) {
  if (!pool) return null;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `UPDATE sites SET enabled = $2, updated_at = NOW()
        WHERE site_key = $1
      RETURNING site_key, name, enabled, updated_at`,
      [siteKey, enabled]
    );
    if (!result.rows[0]) {
      await client.query('ROLLBACK');
      return null;
    }
    await client.query(
      `INSERT INTO admin_audits (actor, action, target, details)
       VALUES ($1, 'set_site_enabled', $2, $3::jsonb)`,
      [actor, siteKey, JSON.stringify({ enabled })]
    );
    await client.query('COMMIT');
    const row = result.rows[0];
    return { siteKey: row.site_key, name: row.name, enabled: Boolean(row.enabled), updatedAt: row.updated_at };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function close() {
  if (redis?.isOpen) await redis.quit();
  if (pool) await pool.end();
  redis = null;
  pool = null;
  ready = false;
}

function isReady() { return ready; }

module.exports = {
  initialize,
  persistBatch,
  listDelta,
  evaluate,
  authorizeClient,
  getAdminOverview,
  listAdminSites,
  setSiteEnabled,
  close,
  isReady
};
