'use strict';

const fs = require('fs');
const path = require('path');
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

async function close() {
  if (redis?.isOpen) await redis.quit();
  if (pool) await pool.end();
  redis = null;
  pool = null;
  ready = false;
}

function isReady() { return ready; }

module.exports = { initialize, persistBatch, listDelta, evaluate, close, isReady };
