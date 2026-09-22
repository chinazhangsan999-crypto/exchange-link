'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const { createClient } = require('redis');
const {
  DATABASE_URL,
  REDIS_URL,
  IS_PRODUCTION,
  CLIENTS,
  INTERNAL_API_URL,
  PUBLIC_API_URL
} = require('../config/env');
const DecisionService = require('./DecisionService');
const CredentialService = require('./CredentialService');
const { SIGNAL_WEIGHTS } = require('./RiskScoringService');

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
    for (const filename of ['001_initial.sql', '002_alerting.sql', '003_maintenance.sql']) {
      const migration = fs.readFileSync(path.join(__dirname, '..', '..', 'migrations', filename), 'utf8');
      await pool.query(migration);
    }
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

const ACTIONS = new Set(['allow', 'observe', 'silent_challenge', 'strong_challenge', 'deny']);

function scoreForAction(action, current = 0) {
  return Math.max(Number(current) || 0, {
    allow: 0,
    observe: 25,
    silent_challenge: 50,
    strong_challenge: 75,
    deny: 90
  }[action] || 0);
}

async function applyManualControls(siteKey, events, decisions) {
  if (!pool || !decisions.length) return decisions;
  const visitors = [...new Set(decisions.map(item => item.subjectHash))];
  const [overrides, rules] = await Promise.all([
    pool.query(
      `SELECT visitor_hash, action, reason, expires_at
         FROM manual_overrides
        WHERE site_key = $1 AND visitor_hash = ANY($2::text[])
          AND (expires_at IS NULL OR expires_at > NOW())`,
      [siteKey, visitors]
    ),
    pool.query(
      `SELECT id, signal, action, reason, duration_minutes, expires_at
         FROM signal_rules
        WHERE (site_key = $1 OR site_key = '*') AND enabled = TRUE
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY CASE WHEN site_key = $1 THEN 0 ELSE 1 END, created_at DESC`,
      [siteKey]
    )
  ]);
  const overrideByVisitor = new Map(overrides.rows.map(row => [row.visitor_hash, row]));
  const signalsByVisitor = new Map();
  for (const event of events) {
    const set = signalsByVisitor.get(event.visitorHash) || new Set();
    set.add(event.eventType);
    signalsByVisitor.set(event.visitorHash, set);
  }
  const now = Date.now();
  return decisions.map(item => {
    const manual = overrideByVisitor.get(item.subjectHash);
    if (manual && ACTIONS.has(manual.action)) {
      return {
        ...item,
        score: manual.action === 'allow' ? 0 : scoreForAction(manual.action, item.score),
        decision: manual.action,
        reasons: [`manual_override:${manual.reason || manual.action}`],
        expiresAt: manual.expires_at
          ? Math.min(item.expiresAt, new Date(manual.expires_at).getTime())
          : item.expiresAt
      };
    }
    const signals = signalsByVisitor.get(item.subjectHash) || new Set();
    const matched = rules.rows.find(rule => signals.has(rule.signal) && ACTIONS.has(rule.action));
    if (!matched) return item;
    const ruleExpiresAt = matched.expires_at
      ? new Date(matched.expires_at).getTime()
      : matched.duration_minutes == null
        ? now + (10 * 365 * 24 * 60 * 60 * 1000)
        : now + Math.max(1, Number(matched.duration_minutes) || 60) * 60_000;
    return {
      ...item,
      score: matched.action === 'allow' ? 0 : scoreForAction(matched.action, item.score),
      decision: matched.action,
      reasons: [...new Set([...(item.reasons || []), `manual_rule:${matched.id}`])],
      expiresAt: Math.min(item.expiresAt, ruleExpiresAt)
    };
  });
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
  const control = await getSiteControl(siteKey);
  const items = result.rows.map(normalizeDecisionRow).map(item => applyEnforcementControl(item, control));
  return { cursor: items.at(-1)?.sequence || Math.max(0, Number(cursor) || 0), items };
}

async function evaluate(siteKey, visitorHash) {
  const control = await getSiteControl(siteKey);
  if (redis) {
    const cached = await redis.get(redisKey(siteKey, visitorHash));
    if (cached) return applyEnforcementControl(JSON.parse(cached), control);
  }
  if (!pool) return DecisionService.evaluate(siteKey, visitorHash);
  const result = await pool.query(
    `SELECT sequence, site_key, subject_type, subject_hash, score, decision, reasons, policy_version, expires_at
       FROM risk_decisions
      WHERE site_key = $1 AND subject_hash = $2 AND revoked_at IS NULL AND expires_at > NOW()
      ORDER BY sequence DESC LIMIT 1`,
    [siteKey, visitorHash]
  );
  return applyEnforcementControl(
    normalizeDecisionRow(result.rows[0]) || DecisionService.evaluate(siteKey, visitorHash),
    control
  );
}

async function getSiteControl(siteKey) {
  if (!pool) return { enforcementEnabled: true, enforcementMode: 'deny' };
  const result = await pool.query(
    `SELECT enforcement_enabled, enforcement_mode FROM sites WHERE site_key = $1`,
    [siteKey]
  );
  const row = result.rows[0];
  return {
    enforcementEnabled: Boolean(row?.enforcement_enabled),
    enforcementMode: row?.enforcement_mode || 'observe'
  };
}

function applyEnforcementControl(item, control) {
  if (!item) return item;
  if (!control?.enforcementEnabled || control.enforcementMode === 'observe') {
    return { ...item, decision: item.decision === 'allow' ? 'allow' : 'observe' };
  }
  const rank = { allow: 0, observe: 1, silent_challenge: 2, strong_challenge: 3, deny: 4 };
  const ceiling = rank[control.enforcementMode] ?? 1;
  if ((rank[item.decision] ?? 0) <= ceiling) return item;
  return { ...item, decision: control.enforcementMode };
}

function secretHash(secret) {
  return crypto.createHash('sha256').update(String(secret || '')).digest('hex');
}

function endpointForTransport(transport) {
  return transport === 'https' ? PUBLIC_API_URL : INTERNAL_API_URL;
}

function normalizeSiteUrls(values) {
  const unique = new Map();
  for (const raw of Array.isArray(values) ? values.slice(0, 100) : []) {
    try {
      const parsed = new URL(String(raw?.url || raw || '').trim());
      if (!['http:', 'https:'].includes(parsed.protocol)) continue;
      parsed.hash = '';
      parsed.search = '';
      const normalized = parsed.toString().replace(/\/$/, '');
      if (!unique.has(normalized)) {
        unique.set(normalized, {
          url: normalized,
          hostname: parsed.hostname.toLowerCase(),
          isPrimary: raw?.isPrimary === true
        });
      }
    } catch { /* 忽略无效网址，由控制层对空结果给出提示。 */ }
  }
  const urls = [...unique.values()];
  if (urls.length && !urls.some(item => item.isPrimary)) urls[0].isPrimary = true;
  let primarySeen = false;
  for (const item of urls) {
    if (item.isPrimary && !primarySeen) primarySeen = true;
    else item.isPrimary = false;
  }
  return urls;
}

async function resolveClientAccess(clientId, siteKey) {
  if (!pool) {
    const secret = CLIENTS[clientId];
    return secret ? { ok: true, secret, clientId, siteKey, legacy: true } : { ok: false, reason: 'unknown_client' };
  }
  const result = await pool.query(
    `SELECT c.*, s.enabled AS site_enabled, s.collection_enabled, s.enforcement_enabled, s.enforcement_mode
       FROM api_clients c JOIN sites s ON s.site_key = c.site_key
      WHERE c.client_id = $1`,
    [clientId]
  );
  const row = result.rows[0];
  if (!row) {
    const secret = CLIENTS[clientId];
    return secret ? { ok: true, secret, clientId, siteKey, legacy: true } : { ok: false, reason: 'unknown_client' };
  }
  if (row.site_key !== siteKey) return { ok: false, reason: 'site_mismatch' };
  if (!row.site_enabled || !row.enabled || !row.collection_enabled) {
    return { ok: false, reason: 'integration_disabled' };
  }
  const secret = CredentialService.decrypt(row) || CLIENTS[clientId];
  if (!secret) return { ok: false, reason: 'credential_unavailable' };
  return {
    ok: true,
    secret,
    clientId,
    siteKey,
    enforcementEnabled: Boolean(row.enforcement_enabled),
    enforcementMode: row.enforcement_mode || 'observe'
  };
}

async function markClientUsed(clientId) {
  if (!pool) return;
  await pool.query(
    `UPDATE api_clients SET last_used_at = NOW(), last_error = ''
      WHERE client_id = $1
        AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute')`,
    [clientId]
  );
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

async function saveIntegration(input, actor = 'risk-admin') {
  if (!pool) throw new Error('数据库未连接');
  const urls = normalizeSiteUrls(input.urls);
  if (!urls.length) throw new Error('至少需要一个有效站点网址');
  const transport = input.transport === 'https' ? 'https' : 'internal';
  const endpointUrl = endpointForTransport(transport);
  const mode = ['observe', 'silent_challenge', 'strong_challenge', 'deny'].includes(input.enforcementMode)
    ? input.enforcementMode : 'observe';
  const client = await pool.connect();
  let issuedSecret = null;
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO sites
         (site_key, name, enabled, collection_enabled, enforcement_enabled, enforcement_mode)
       VALUES ($1, $2, TRUE, $3, $4, $5)
       ON CONFLICT (site_key) DO UPDATE SET
         name = EXCLUDED.name,
         collection_enabled = EXCLUDED.collection_enabled,
         enforcement_enabled = EXCLUDED.enforcement_enabled,
         enforcement_mode = EXCLUDED.enforcement_mode,
         updated_at = NOW()`,
      [input.siteKey, input.name, input.collectionEnabled !== false, input.enforcementEnabled === true, mode]
    );
    await client.query('DELETE FROM site_urls WHERE site_key = $1', [input.siteKey]);
    for (const item of urls) {
      await client.query(
        `INSERT INTO site_urls (site_key, url, hostname, is_primary, enabled)
         VALUES ($1, $2, $3, $4, TRUE)`,
        [input.siteKey, item.url, item.hostname, item.isPrimary]
      );
    }
    const existing = await client.query(
      'SELECT client_id, site_key FROM api_clients WHERE client_id = $1 FOR UPDATE',
      [input.clientId]
    );
    if (existing.rows[0] && existing.rows[0].site_key !== input.siteKey) {
      throw new Error('客户端标识已绑定其他导航站');
    }
    if (!existing.rows[0]) {
      issuedSecret = CredentialService.generateSecret();
      const encrypted = CredentialService.encrypt(issuedSecret);
      await client.query(
        `INSERT INTO api_clients
          (client_id, site_key, name, transport, endpoint_url, secret_hash,
           secret_ciphertext, secret_iv, secret_tag, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE)`,
        [input.clientId, input.siteKey, input.clientName || input.name, transport, endpointUrl,
          secretHash(issuedSecret), encrypted.ciphertext, encrypted.iv, encrypted.tag]
      );
    } else {
      await client.query(
        `UPDATE api_clients SET name = $2, transport = $3, endpoint_url = $4
          WHERE client_id = $1`,
        [input.clientId, input.clientName || input.name, transport, endpointUrl]
      );
    }
    await client.query(
      `INSERT INTO admin_audits (actor, action, target, details)
       VALUES ($1, 'save_integration', $2, $3::jsonb)`,
      [actor, input.siteKey, JSON.stringify({ clientId: input.clientId, transport, urlCount: urls.length })]
    );
    await client.query('COMMIT');
    return { siteKey: input.siteKey, clientId: input.clientId, secret: issuedSecret, endpointUrl, transport };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function rotateClientSecret(clientId, actor = 'risk-admin') {
  if (!pool) throw new Error('数据库未连接');
  const secret = CredentialService.generateSecret();
  const encrypted = CredentialService.encrypt(secret);
  const result = await pool.query(
    `UPDATE api_clients SET
       secret_hash = $2, secret_ciphertext = $3, secret_iv = $4, secret_tag = $5,
       key_version = key_version + 1
     WHERE client_id = $1
     RETURNING site_key, endpoint_url, transport, key_version`,
    [clientId, secretHash(secret), encrypted.ciphertext, encrypted.iv, encrypted.tag]
  );
  if (!result.rows[0]) return null;
  await pool.query(
    `INSERT INTO admin_audits (actor, action, target, details)
     VALUES ($1, 'rotate_client_secret', $2, $3::jsonb)`,
    [actor, clientId, JSON.stringify({ keyVersion: result.rows[0].key_version })]
  );
  return { clientId, secret, ...result.rows[0] };
}

async function setClientEnabled(clientId, enabled, actor = 'risk-admin') {
  if (!pool) return null;
  const result = await pool.query(
    `UPDATE api_clients SET enabled = $2 WHERE client_id = $1
     RETURNING client_id, site_key, enabled`,
    [clientId, enabled]
  );
  if (!result.rows[0]) return null;
  await pool.query(
    `INSERT INTO admin_audits (actor, action, target, details)
     VALUES ($1, 'set_client_enabled', $2, $3::jsonb)`,
    [actor, clientId, JSON.stringify({ enabled })]
  );
  return result.rows[0];
}

async function setSiteControls(siteKey, input, actor = 'risk-admin') {
  if (!pool) return null;
  const mode = ['observe', 'silent_challenge', 'strong_challenge', 'deny'].includes(input.enforcementMode)
    ? input.enforcementMode : 'observe';
  const result = await pool.query(
    `UPDATE sites SET collection_enabled = $2, enforcement_enabled = $3,
       enforcement_mode = $4, updated_at = NOW()
     WHERE site_key = $1
     RETURNING site_key, collection_enabled, enforcement_enabled, enforcement_mode`,
    [siteKey, input.collectionEnabled !== false, input.enforcementEnabled === true, mode]
  );
  if (!result.rows[0]) return null;
  await pool.query(
    `INSERT INTO admin_audits (actor, action, target, details)
     VALUES ($1, 'set_site_controls', $2, $3::jsonb)`,
    [actor, siteKey, JSON.stringify({
      collectionEnabled: input.collectionEnabled !== false,
      enforcementEnabled: input.enforcementEnabled === true,
      enforcementMode: mode
    })]
  );
  return result.rows[0];
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
    `SELECT s.site_key, s.name, s.enabled, s.collection_enabled,
            s.enforcement_enabled, s.enforcement_mode, s.created_at, s.updated_at,
            (SELECT COUNT(*)::int FROM risk_events e
              WHERE e.site_key = s.site_key AND e.created_at >= NOW() - INTERVAL '24 hours') AS events_24h,
            (SELECT COUNT(*)::int FROM risk_decisions d
              WHERE d.site_key = s.site_key AND d.created_at >= NOW() - INTERVAL '24 hours') AS decisions_24h,
            (SELECT MAX(c.last_used_at) FROM api_clients c WHERE c.site_key = s.site_key) AS last_used_at,
            COALESCE((SELECT jsonb_agg(jsonb_build_object(
                                'url', u.url, 'hostname', u.hostname,
                                'isPrimary', u.is_primary, 'enabled', u.enabled)
                               ORDER BY u.is_primary DESC, u.id)
                         FROM site_urls u WHERE u.site_key = s.site_key), '[]'::jsonb) AS urls,
            COALESCE((
              SELECT jsonb_agg(jsonb_build_object(
                                'clientId', c.client_id, 'name', c.name,
                                'enabled', c.enabled, 'transport', c.transport,
                                'endpointUrl', c.endpoint_url, 'keyVersion', c.key_version,
                                'lastUsedAt', c.last_used_at, 'lastError', c.last_error)
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
    collectionEnabled: Boolean(row.collection_enabled),
    enforcementEnabled: Boolean(row.enforcement_enabled),
    enforcementMode: row.enforcement_mode || 'observe',
    events24h: Number(row.events_24h) || 0,
    decisions24h: Number(row.decisions_24h) || 0,
    lastUsedAt: row.last_used_at,
    urls: row.urls || [],
    clients: row.clients || [],
    createdAt: row.created_at,
    updatedAt: row.updated_at
  }));
}

async function getRiskSummary(siteKey = '') {
  if (!pool) return { visitors24h: 0, suspects24h: 0, blocked24h: 0, challenged24h: 0, signals: [] };
  const params = siteKey ? [siteKey] : [];
  const siteFilter = siteKey ? 'AND site_key = $1' : '';
  const [events, decisions, signals] = await Promise.all([
    pool.query(
      `SELECT COUNT(DISTINCT visitor_hash)::int AS visitors_24h
         FROM risk_events WHERE created_at >= NOW() - INTERVAL '24 hours' ${siteFilter}`,
      params
    ),
    pool.query(
      `WITH latest AS (
         SELECT DISTINCT ON (site_key, subject_hash) score, decision
           FROM risk_decisions
          WHERE created_at >= NOW() - INTERVAL '24 hours' ${siteFilter}
          ORDER BY site_key, subject_hash, sequence DESC
       ) SELECT COUNT(*) FILTER (WHERE score >= 25)::int AS suspects_24h,
                COUNT(*) FILTER (WHERE decision = 'deny')::int AS blocked_24h,
                COUNT(*) FILTER (WHERE decision IN ('silent_challenge', 'strong_challenge'))::int AS challenged_24h
           FROM latest`,
      params
    ),
    pool.query(
      `SELECT event_type, COUNT(*)::int AS count,
              COUNT(DISTINCT visitor_hash)::int AS visitors
         FROM risk_events WHERE created_at >= NOW() - INTERVAL '24 hours' ${siteFilter}
        GROUP BY event_type ORDER BY count DESC LIMIT 12`,
      params
    )
  ]);
  return {
    visitors24h: Number(events.rows[0]?.visitors_24h) || 0,
    suspects24h: Number(decisions.rows[0]?.suspects_24h) || 0,
    blocked24h: Number(decisions.rows[0]?.blocked_24h) || 0,
    challenged24h: Number(decisions.rows[0]?.challenged_24h) || 0,
    signals: signals.rows.map(row => ({ signal: row.event_type, count: Number(row.count), visitors: Number(row.visitors) }))
  };
}

async function listSuspects({ siteKey = '', page = 1, limit = 50, minScore = 25 } = {}) {
  if (!pool) return { page: 1, limit, total: 0, items: [] };
  const safePage = Math.max(1, Number(page) || 1);
  const safeLimit = Math.max(1, Math.min(100, Number(limit) || 50));
  const safeScore = Math.max(0, Math.min(100, Number(minScore) || 25));
  const params = [safeScore];
  const siteClause = siteKey ? `AND d.site_key = $${params.push(siteKey)}` : '';
  const base = `WITH latest AS (
      SELECT DISTINCT ON (d.site_key, d.subject_hash)
             d.site_key, d.subject_hash, d.score, d.decision, d.reasons,
             d.created_at, d.expires_at
        FROM risk_decisions d
       WHERE d.created_at >= NOW() - INTERVAL '24 hours' AND d.score >= $1 ${siteClause}
       ORDER BY d.site_key, d.subject_hash, d.sequence DESC
    )`;
  const countResult = await pool.query(`${base} SELECT COUNT(*)::int AS total FROM latest`, params);
  const offsetParam = params.length + 1;
  const limitParam = params.length + 2;
  const result = await pool.query(
    `${base}
     SELECT l.*, s.name AS site_name,
            COALESCE(e.event_count, 0)::int AS event_count,
            e.first_seen, e.last_seen, e.signal_details,
            o.action AS manual_action, o.reason AS manual_reason, o.expires_at AS manual_expires_at
       FROM latest l
       JOIN sites s ON s.site_key = l.site_key
       LEFT JOIN LATERAL (
         SELECT COALESCE(SUM(g.signal_count), 0)::int AS event_count,
                MIN(g.first_seen) AS first_seen, MAX(g.last_seen) AS last_seen,
                COALESCE(jsonb_agg(jsonb_build_object(
                  'signal', g.event_type, 'count', g.signal_count,
                  'firstSeen', g.first_seen, 'lastSeen', g.last_seen,
                  'latestEvidence', g.latest_evidence
                ) ORDER BY g.signal_count DESC), '[]'::jsonb) AS signal_details
           FROM (
             SELECT re.event_type, COUNT(*)::int AS signal_count,
                    MIN(re.occurred_at) AS first_seen, MAX(re.occurred_at) AS last_seen,
                    (ARRAY_AGG(re.evidence ORDER BY re.occurred_at DESC))[1] AS latest_evidence
               FROM risk_events re
              WHERE re.site_key = l.site_key AND re.visitor_hash = l.subject_hash
                AND re.created_at >= NOW() - INTERVAL '24 hours'
              GROUP BY re.event_type
           ) g
       ) e ON TRUE
       LEFT JOIN manual_overrides o ON o.site_key = l.site_key AND o.visitor_hash = l.subject_hash
                                    AND (o.expires_at IS NULL OR o.expires_at > NOW())
      ORDER BY l.score DESC, l.created_at DESC
      OFFSET $${offsetParam} LIMIT $${limitParam}`,
    [...params, (safePage - 1) * safeLimit, safeLimit]
  );
  return {
    page: safePage,
    limit: safeLimit,
    total: Number(countResult.rows[0]?.total) || 0,
    items: result.rows.map(row => ({
      siteKey: row.site_key,
      siteName: row.site_name,
      visitorHash: row.subject_hash,
      score: Number(row.score),
      decision: row.decision,
      reasons: row.reasons || [],
      signals: (row.signal_details || []).map(detail => ({
        signal: detail.signal,
        count: Number(detail.count) || 0,
        scoreImpact: Number(SIGNAL_WEIGHTS[detail.signal] || 0),
        firstSeen: detail.firstSeen,
        lastSeen: detail.lastSeen,
        latestEvidence: detail.latestEvidence || {}
      })),
      eventCount: Number(row.event_count) || 0,
      firstSeen: row.first_seen,
      lastSeen: row.last_seen,
      decisionAt: row.created_at,
      expiresAt: row.expires_at,
      manualAction: row.manual_action,
      manualReason: row.manual_reason,
      manualExpiresAt: row.manual_expires_at
    }))
  };
}

async function getSuspectDetail(siteKey, visitorHash) {
  if (!pool) return null;
  const [site, decision, events] = await Promise.all([
    pool.query('SELECT site_key, name FROM sites WHERE site_key = $1', [siteKey]),
    pool.query(
      `SELECT score, decision, reasons, created_at, expires_at
         FROM risk_decisions WHERE site_key = $1 AND subject_hash = $2
        ORDER BY sequence DESC LIMIT 1`,
      [siteKey, visitorHash]
    ),
    pool.query(
      `SELECT event_id, event_type, occurred_at, evidence
         FROM risk_events WHERE site_key = $1 AND visitor_hash = $2
        ORDER BY occurred_at DESC LIMIT 100`,
      [siteKey, visitorHash]
    )
  ]);
  if (!site.rows[0] || !decision.rows[0]) return null;
  const groupedSignals = new Map();
  for (const row of events.rows) {
    const current = groupedSignals.get(row.event_type) || {
      signal: row.event_type,
      count: 0,
      scoreImpact: Number(SIGNAL_WEIGHTS[row.event_type] || 0),
      firstSeen: row.occurred_at,
      lastSeen: row.occurred_at,
      latestEvidence: row.evidence || {}
    };
    current.count += 1;
    if (new Date(row.occurred_at) < new Date(current.firstSeen)) current.firstSeen = row.occurred_at;
    if (new Date(row.occurred_at) > new Date(current.lastSeen)) current.lastSeen = row.occurred_at;
    groupedSignals.set(row.event_type, current);
  }
  return {
    siteKey,
    siteName: site.rows[0].name,
    visitorHash,
    score: Number(decision.rows[0].score),
    decision: decision.rows[0].decision,
    reasons: decision.rows[0].reasons || [],
    signals: [...groupedSignals.values()].sort((a, b) => Math.abs(b.scoreImpact) - Math.abs(a.scoreImpact) || b.count - a.count),
    decisionAt: decision.rows[0].created_at,
    expiresAt: decision.rows[0].expires_at,
    events: events.rows.map(row => ({
      eventId: row.event_id,
      eventType: row.event_type,
      occurredAt: row.occurred_at,
      evidence: row.evidence || {}
    }))
  };
}

async function applyManualDecision(
  siteKey, visitorHash, action, durationMinutes, reason,
  actor = 'risk-admin', permanent = false, globalRule = null
) {
  if (!pool || !ACTIONS.has(action)) return null;
  const minutes = Math.max(1, Math.min(43_200, Number(durationMinutes) || 60));
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`decision:${siteKey}`]);
    await client.query(
      `INSERT INTO manual_overrides
        (site_key, visitor_hash, action, reason, expires_at, created_by)
       VALUES ($1, $2, $3, $4,
         CASE WHEN $7::boolean THEN NULL ELSE NOW() + ($5 * INTERVAL '1 minute') END, $6)
       ON CONFLICT (site_key, visitor_hash) DO UPDATE SET
         action = EXCLUDED.action, reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at,
         created_by = EXCLUDED.created_by, updated_at = NOW()`,
      [siteKey, visitorHash, action, reason, minutes, actor, permanent === true]
    );
    const seq = await client.query('SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence FROM risk_decisions');
    const sequence = Number(seq.rows[0].sequence);
    const expiresAt = permanent
      ? Date.now() + (10 * 365 * 24 * 60 * 60_000)
      : Date.now() + minutes * 60_000;
    const item = {
      sequence, siteKey, subjectType: 'visitor', subjectHash: visitorHash,
      score: action === 'allow' ? 0 : scoreForAction(action),
      decision: action, reasons: [`manual_override:${reason || action}`],
      policyVersion: 'manual-1', expiresAt
    };
    await client.query(
      `INSERT INTO risk_decisions
        (sequence, site_key, subject_type, subject_hash, score, decision, reasons, policy_version, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,to_timestamp($9 / 1000.0))`,
      [sequence, siteKey, 'visitor', visitorHash, item.score, action,
        JSON.stringify(item.reasons), item.policyVersion, expiresAt]
    );
    await client.query(
      `INSERT INTO admin_audits (actor, action, target, details)
       VALUES ($1, 'manual_visitor_action', $2, $3::jsonb)`,
      [actor, `${siteKey}:${visitorHash}`, JSON.stringify({
        action, minutes: permanent ? null : minutes, permanent, reason,
        applyToAllSites: Boolean(globalRule), ruleSignal: globalRule?.signal || null
      })]
    );
    let globalRuleId = null;
    if (globalRule?.signal) {
      const rule = await client.query(
        `INSERT INTO signal_rules
          (site_key, signal, action, reason, enabled, duration_minutes, created_by, expires_at)
         VALUES ('*', $1, $2, $3, TRUE, $4, $5, NULL)
         RETURNING id`,
        [globalRule.signal, action, reason, permanent ? null : minutes, actor]
      );
      globalRuleId = Number(rule.rows[0].id);
      await client.query(
        `INSERT INTO admin_audits (actor, action, target, details)
         VALUES ($1, 'create_signal_rule_from_visitor', $2, $3::jsonb)`,
        [actor, String(globalRuleId), JSON.stringify({
          siteKey: '*', sourceSiteKey: siteKey, visitorHash,
          signal: globalRule.signal, action, permanent, durationMinutes: permanent ? null : minutes, reason
        })]
      );
    }
    await client.query('COMMIT');
    DecisionService.setSequenceFloor(sequence);
    if (redis) await redis.set(redisKey(siteKey, visitorHash), JSON.stringify(item), { PX: expiresAt - Date.now() });
    return { ...item, globalRuleId };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function clearManualDecision(siteKey, visitorHash, actor = 'risk-admin') {
  if (!pool) return false;
  const result = await pool.query(
    'DELETE FROM manual_overrides WHERE site_key = $1 AND visitor_hash = $2',
    [siteKey, visitorHash]
  );
  if (redis) await redis.del(redisKey(siteKey, visitorHash));
  await pool.query(
    `INSERT INTO admin_audits (actor, action, target, details)
     VALUES ($1, 'clear_manual_visitor_action', $2, '{}'::jsonb)`,
    [actor, `${siteKey}:${visitorHash}`]
  );
  return result.rowCount > 0;
}

async function listSignalRules() {
  if (!pool) return [];
  const result = await pool.query(
    `SELECT r.*, COALESCE(s.name, '任意站点') AS site_name FROM signal_rules r
       LEFT JOIN sites s ON s.site_key = r.site_key ORDER BY r.created_at DESC`
  );
  return result.rows.map(row => ({
    id: Number(row.id), siteKey: row.site_key, siteName: row.site_name,
    scope: row.site_key === '*' ? 'all' : 'site',
    signal: row.signal, action: row.action, reason: row.reason,
    enabled: Boolean(row.enabled),
    permanent: row.duration_minutes == null,
    durationMinutes: row.duration_minutes == null ? null : Number(row.duration_minutes),
    expiresAt: row.expires_at, createdAt: row.created_at
  }));
}

async function previewSignalRule(siteKey, signal) {
  if (!pool) return { events24h: 0, visitors24h: 0 };
  const anySite = siteKey === '*';
  const result = await pool.query(
    `SELECT COUNT(*)::int AS events_24h, COUNT(DISTINCT (site_key, visitor_hash))::int AS visitors_24h
       FROM risk_events WHERE event_type = $1
        AND ($2::boolean OR site_key = $3)
        AND created_at >= NOW() - INTERVAL '24 hours'`,
    [signal, anySite, siteKey]
  );
  return {
    events24h: Number(result.rows[0]?.events_24h) || 0,
    visitors24h: Number(result.rows[0]?.visitors_24h) || 0
  };
}

async function createSignalRule(input, actor = 'risk-admin') {
  if (!pool || !ACTIONS.has(input.action)) return null;
  const permanent = input.permanent === true;
  const minutes = permanent ? null : Math.max(1, Math.min(43_200, Number(input.durationMinutes) || 60));
  const result = await pool.query(
    `INSERT INTO signal_rules
      (site_key, signal, action, reason, enabled, duration_minutes, created_by, expires_at)
     VALUES ($1,$2,$3,$4,TRUE,$5,$6,
       CASE WHEN $7::int > 0 THEN NOW() + ($7 * INTERVAL '1 minute') ELSE NULL END)
     RETURNING id`,
    [input.siteKey, input.signal, input.action, input.reason || '', minutes, actor,
      Math.max(0, Math.min(525_600, Number(input.ruleExpiresMinutes) || 0))]
  );
  await pool.query(
    `INSERT INTO admin_audits (actor, action, target, details)
     VALUES ($1, 'create_signal_rule', $2, $3::jsonb)`,
    [actor, String(result.rows[0].id), JSON.stringify(input)]
  );
  return Number(result.rows[0].id);
}

async function setSignalRuleEnabled(id, enabled, actor = 'risk-admin') {
  if (!pool) return null;
  const result = await pool.query(
    'UPDATE signal_rules SET enabled = $2, updated_at = NOW() WHERE id = $1 RETURNING id, enabled',
    [id, enabled]
  );
  if (!result.rows[0]) return null;
  await pool.query(
    `INSERT INTO admin_audits (actor, action, target, details)
     VALUES ($1, 'set_signal_rule_enabled', $2, $3::jsonb)`,
    [actor, String(id), JSON.stringify({ enabled })]
  );
  return { id: Number(id), enabled: Boolean(enabled) };
}

async function deleteSignalRule(id, actor = 'risk-admin') {
  if (!pool) return false;
  const result = await pool.query('DELETE FROM signal_rules WHERE id = $1', [id]);
  await pool.query(
    `INSERT INTO admin_audits (actor, action, target, details)
     VALUES ($1, 'delete_signal_rule', $2, '{}'::jsonb)`,
    [actor, String(id)]
  );
  return result.rowCount > 0;
}

async function listAdminAudits(limit = 100) {
  if (!pool) return [];
  const result = await pool.query(
    `SELECT actor, action, target, details, created_at
       FROM admin_audits ORDER BY created_at DESC LIMIT $1`,
    [Math.max(1, Math.min(500, Number(limit) || 100))]
  );
  return result.rows.map(row => ({
    actor: row.actor, action: row.action, target: row.target,
    details: row.details || {}, createdAt: row.created_at
  }));
}

function encryptedColumns(prefix, encrypted) {
  return {
    [`${prefix}_ciphertext`]: encrypted?.ciphertext || null,
    [`${prefix}_iv`]: encrypted?.iv || null,
    [`${prefix}_tag`]: encrypted?.tag || null
  };
}

async function getAlertSettings({ includeSecrets = false } = {}) {
  if (!pool) return null;
  const result = await pool.query('SELECT * FROM alert_settings WHERE id = 1');
  const row = result.rows[0];
  if (!row) return null;
  const settings = {
    enabled: Boolean(row.enabled),
    telegramEnabled: Boolean(row.telegram_enabled),
    telegramChatId: row.telegram_chat_id || '',
    telegramConfigured: Boolean(row.telegram_token_ciphertext),
    barkEnabled: Boolean(row.bark_enabled),
    barkServerUrl: row.bark_server_url || 'https://api.day.app',
    barkGroup: row.bark_group || '风险中心',
    barkConfigured: Boolean(row.bark_key_ciphertext),
    deniedCount5m: Number(row.denied_count_5m) || 10,
    suspiciousCount10m: Number(row.suspicious_count_10m) || 20,
    challengeFailureCount10m: Number(row.challenge_failure_count_10m) || 10,
    challengeFailureRatio: Number(row.challenge_failure_ratio) || 0.4,
    replayCount5m: Number(row.replay_count_5m) || 3,
    crossSiteCount10m: Number(row.cross_site_count_10m) || 3,
    cooldownMinutes: Number(row.cooldown_minutes) || 30,
    hourlyDigestEnabled: Boolean(row.hourly_digest_enabled),
    dailyDigestEnabled: Boolean(row.daily_digest_enabled),
    telegramIntervalMs: Math.max(1000, Number(row.telegram_interval_ms) || 1200),
    barkIntervalMs: Math.max(1000, Number(row.bark_interval_ms) || 2000),
    upstreamUpdateAlertEnabled: Boolean(row.upstream_update_alert_enabled),
    upstreamCheckIntervalHours: Math.max(1, Number(row.upstream_check_interval_hours) || 6),
    updatedAt: row.updated_at
  };
  if (includeSecrets) {
    settings.telegramToken = CredentialService.decrypt({
      secret_ciphertext: row.telegram_token_ciphertext,
      secret_iv: row.telegram_token_iv,
      secret_tag: row.telegram_token_tag
    });
    settings.barkDeviceKey = CredentialService.decrypt({
      secret_ciphertext: row.bark_key_ciphertext,
      secret_iv: row.bark_key_iv,
      secret_tag: row.bark_key_tag
    });
  }
  return settings;
}

async function saveAlertSettings(input, actor = 'risk-admin') {
  if (!pool) return null;
  const current = await getAlertSettings({ includeSecrets: true });
  const telegramToken = String(input.telegramToken || '').trim() || current?.telegramToken || '';
  const barkDeviceKey = String(input.barkDeviceKey || '').trim() || current?.barkDeviceKey || '';
  const telegram = telegramToken ? encryptedColumns('telegram_token', CredentialService.encrypt(telegramToken)) : encryptedColumns('telegram_token');
  const bark = barkDeviceKey ? encryptedColumns('bark_key', CredentialService.encrypt(barkDeviceKey)) : encryptedColumns('bark_key');
  const value = (name, fallback, min, max) => Math.max(min, Math.min(max, Number(input[name]) || fallback));
  await pool.query(
    `UPDATE alert_settings SET
       enabled=$1, telegram_enabled=$2, telegram_chat_id=$3,
       telegram_token_ciphertext=$4, telegram_token_iv=$5, telegram_token_tag=$6,
       bark_enabled=$7, bark_server_url=$8, bark_group=$9,
       bark_key_ciphertext=$10, bark_key_iv=$11, bark_key_tag=$12,
       denied_count_5m=$13, suspicious_count_10m=$14,
       challenge_failure_count_10m=$15, challenge_failure_ratio=$16,
       replay_count_5m=$17, cross_site_count_10m=$18, cooldown_minutes=$19,
       hourly_digest_enabled=$20, daily_digest_enabled=$21,
       telegram_interval_ms=$22, bark_interval_ms=$23,
       upstream_update_alert_enabled=$24, upstream_check_interval_hours=$25, updated_at=NOW()
     WHERE id=1`,
    [input.enabled === true, input.telegramEnabled === true, String(input.telegramChatId || '').trim().slice(0, 100),
      telegram.telegram_token_ciphertext, telegram.telegram_token_iv, telegram.telegram_token_tag,
      input.barkEnabled === true, String(input.barkServerUrl || 'https://api.day.app').trim().replace(/\/$/, '').slice(0, 300),
      String(input.barkGroup || '风险中心').trim().slice(0, 80),
      bark.bark_key_ciphertext, bark.bark_key_iv, bark.bark_key_tag,
      value('deniedCount5m', 10, 1, 10000), value('suspiciousCount10m', 20, 1, 10000),
      value('challengeFailureCount10m', 10, 1, 10000), value('challengeFailureRatio', 0.4, 0.01, 1),
      value('replayCount5m', 3, 1, 10000), value('crossSiteCount10m', 3, 2, 1000),
      value('cooldownMinutes', 30, 5, 1440), input.hourlyDigestEnabled === true, input.dailyDigestEnabled === true,
      value('telegramIntervalMs', 1200, 1000, 60000), value('barkIntervalMs', 2000, 1000, 60000),
      input.upstreamUpdateAlertEnabled === true, value('upstreamCheckIntervalHours', 6, 1, 168)]
  );
  await pool.query(
    `INSERT INTO admin_audits (actor, action, target, details)
     VALUES ($1, 'save_alert_settings', 'alerts', $2::jsonb)`,
    [actor, JSON.stringify({ enabled: input.enabled === true, telegramEnabled: input.telegramEnabled === true, barkEnabled: input.barkEnabled === true })]
  );
  return getAlertSettings();
}

async function listAlertCandidates(settings) {
  if (!pool) return [];
  const candidates = [];
  const denied = await pool.query(
    `SELECT d.site_key, COALESCE(s.name, d.site_key) AS site_name,
            COUNT(DISTINCT d.subject_hash)::int AS visitors, COUNT(*)::int AS events
       FROM risk_decisions d LEFT JOIN sites s ON s.site_key=d.site_key
      WHERE d.created_at >= NOW() - INTERVAL '5 minutes' AND d.decision='deny'
      GROUP BY d.site_key, s.name HAVING COUNT(DISTINCT d.subject_hash) >= $1`,
    [settings.deniedCount5m]
  );
  for (const row of denied.rows) candidates.push({ key: `deny_5m:${row.site_key}`, kind: 'deny_5m', severity: 'critical', siteKey: row.site_key, siteName: row.site_name, value: Number(row.visitors), details: { visitors: Number(row.visitors), events: Number(row.events), window: '5分钟' } });

  const suspicious = await pool.query(
    `WITH latest AS (
       SELECT DISTINCT ON (site_key, subject_hash) site_key, subject_hash, score
         FROM risk_decisions WHERE created_at >= NOW() - INTERVAL '10 minutes'
        ORDER BY site_key, subject_hash, sequence DESC)
     SELECT l.site_key, COALESCE(s.name,l.site_key) AS site_name, COUNT(*)::int AS visitors
       FROM latest l LEFT JOIN sites s ON s.site_key=l.site_key WHERE l.score >= 25
      GROUP BY l.site_key,s.name HAVING COUNT(*) >= $1`,
    [settings.suspiciousCount10m]
  );
  for (const row of suspicious.rows) candidates.push({ key: `suspicious_10m:${row.site_key}`, kind: 'suspicious_10m', severity: 'high', siteKey: row.site_key, siteName: row.site_name, value: Number(row.visitors), details: { visitors: Number(row.visitors), window: '10分钟' } });

  const failures = await pool.query(
    `SELECT e.site_key, COALESCE(s.name,e.site_key) AS site_name,
            COUNT(DISTINCT e.visitor_hash) FILTER (WHERE e.event_type='challenge_failed')::int AS failed,
            COUNT(DISTINCT e.visitor_hash)::int AS total
       FROM risk_events e LEFT JOIN sites s ON s.site_key=e.site_key
      WHERE e.created_at >= NOW() - INTERVAL '10 minutes'
      GROUP BY e.site_key,s.name`, []);
  for (const row of failures.rows) {
    const failed = Number(row.failed) || 0; const total = Number(row.total) || 0; const ratio = total ? failed / total : 0;
    if (failed >= settings.challengeFailureCount10m && ratio >= settings.challengeFailureRatio) candidates.push({ key: `challenge_fail:${row.site_key}`, kind: 'challenge_fail', severity: 'high', siteKey: row.site_key, siteName: row.site_name, value: failed, details: { failed, total, ratio, window: '10分钟' } });
  }

  const replay = await pool.query(
    `SELECT e.site_key, COALESCE(s.name,e.site_key) AS site_name,
            COUNT(DISTINCT e.visitor_hash)::int AS visitors, COUNT(*)::int AS events
       FROM risk_events e LEFT JOIN sites s ON s.site_key=e.site_key
      WHERE e.created_at >= NOW() - INTERVAL '5 minutes' AND e.event_type='token_replay'
      GROUP BY e.site_key,s.name HAVING COUNT(*) >= $1`, [settings.replayCount5m]);
  for (const row of replay.rows) candidates.push({ key: `token_replay:${row.site_key}`, kind: 'token_replay', severity: 'critical', siteKey: row.site_key, siteName: row.site_name, value: Number(row.events), details: { visitors: Number(row.visitors), events: Number(row.events), window: '5分钟' } });

  const crossSite = await pool.query(
    `SELECT event_type, COUNT(DISTINCT site_key)::int AS sites,
            COUNT(DISTINCT (site_key, visitor_hash))::int AS visitors
       FROM risk_events WHERE created_at >= NOW() - INTERVAL '10 minutes'
        AND event_type NOT IN ('valid_browser_access','valid_read_token','challenge_passed','browser_challenge_passed','normal_dwell','outbound_interaction')
      GROUP BY event_type HAVING COUNT(DISTINCT site_key) >= $1`, [settings.crossSiteCount10m]);
  for (const row of crossSite.rows) candidates.push({ key: `cross_site:${row.event_type}`, kind: 'cross_site', severity: 'high', siteKey: null, siteName: '所有站点', value: Number(row.sites), details: { signal: row.event_type, sites: Number(row.sites), visitors: Number(row.visitors), window: '10分钟' } });
  return candidates;
}

async function claimAlertNotifications(candidates, cooldownMinutes) {
  if (!pool || !candidates.length) return [];
  const client = await pool.connect(); const claimed = [];
  try {
    await client.query('BEGIN');
    for (const item of candidates) {
      const result = await client.query(
        `INSERT INTO alert_states
          (alert_key,kind,site_key,severity,current_value,last_seen_at,details)
         VALUES ($1,$2,$3,$4,$5,NOW(),$6::jsonb)
         ON CONFLICT (alert_key) DO UPDATE SET active=TRUE, severity=EXCLUDED.severity,
           current_value=EXCLUDED.current_value,last_seen_at=NOW(),resolved_at=NULL,details=EXCLUDED.details
         RETURNING *, (last_notified_at IS NULL OR last_notified_at <= NOW()-($7::int * INTERVAL '1 minute')
           OR current_value >= GREATEST(last_notified_value * 2, last_notified_value + 5)) AS notify`,
        [item.key,item.kind,item.siteKey,item.severity,item.value,JSON.stringify({ ...item.details, siteName: item.siteName }),cooldownMinutes]
      );
      if (result.rows[0]?.notify) {
        await client.query('UPDATE alert_states SET last_notified_at=NOW(),last_notified_value=current_value WHERE alert_key=$1', [item.key]);
        claimed.push(item);
      }
    }
    await client.query('COMMIT');
    return claimed;
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

async function resolveRecoveredAlerts(cooldownMinutes) {
  if (!pool) return [];
  const result = await pool.query(
    `UPDATE alert_states SET active=FALSE,resolved_at=NOW()
      WHERE active=TRUE AND last_seen_at < NOW()-($1::int * INTERVAL '1 minute')
      RETURNING alert_key,kind,site_key,severity,current_value,details`, [cooldownMinutes]);
  return result.rows.map(row => ({ key: row.alert_key, kind: row.kind, siteKey: row.site_key, severity: row.severity, value: Number(row.current_value), details: row.details || {}, recovered: true }));
}

async function recordAlertDelivery(item) {
  if (!pool) return;
  await pool.query(
    `INSERT INTO alert_delivery_logs (alert_key,provider,success,status_code,error_message,payload_size)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [item.alertKey,item.provider,item.success,item.statusCode || null,String(item.error || '').slice(0,500),item.payloadSize || 0]
  );
}

async function listAlertActivity(limit = 100) {
  if (!pool) return { active: [], deliveries: [] };
  const safeLimit = Math.max(1, Math.min(200, Number(limit) || 100));
  const [states, deliveries] = await Promise.all([
    pool.query('SELECT * FROM alert_states ORDER BY last_seen_at DESC LIMIT $1', [safeLimit]),
    pool.query('SELECT * FROM alert_delivery_logs ORDER BY created_at DESC LIMIT $1', [safeLimit])
  ]);
  return {
    active: states.rows.map(row => ({ alertKey: row.alert_key, kind: row.kind, siteKey: row.site_key, severity: row.severity, active: Boolean(row.active), currentValue: Number(row.current_value), details: row.details || {}, lastSeenAt: row.last_seen_at, lastNotifiedAt: row.last_notified_at, resolvedAt: row.resolved_at })),
    deliveries: deliveries.rows.map(row => ({ id: Number(row.id), alertKey: row.alert_key, provider: row.provider, success: Boolean(row.success), statusCode: row.status_code, error: row.error_message, payloadSize: Number(row.payload_size), createdAt: row.created_at }))
  };
}

async function listMaintenanceProjects() {
  if (!pool) return [];
  const result = await pool.query(
    `SELECT project_key,name,repository,integration_mode,installed_version,
            latest_version,latest_release_at,release_url,last_checked_at,
            follow_status,followed_version,followed_at,ignored_version,
            alerted_version,last_error,updated_at
       FROM maintenance_projects ORDER BY
         CASE integration_mode WHEN 'direct' THEN 1 WHEN 'signal_source' THEN 2 ELSE 3 END,
         name`
  );
  return result.rows.map(row => ({
    projectKey: row.project_key, name: row.name, repository: row.repository,
    integrationMode: row.integration_mode, installedVersion: row.installed_version,
    latestVersion: row.latest_version, latestReleaseAt: row.latest_release_at,
    releaseUrl: row.release_url, lastCheckedAt: row.last_checked_at,
    followStatus: row.follow_status, followedVersion: row.followed_version,
    followedAt: row.followed_at, ignoredVersion: row.ignored_version,
    alertedVersion: row.alerted_version, lastError: row.last_error,
    updatedAt: row.updated_at
  }));
}

async function updateMaintenanceProject(projectKey, release) {
  if (!pool) return null;
  const result = await pool.query(
    `UPDATE maintenance_projects SET
       latest_version=$2,latest_release_at=$3,release_url=$4,last_checked_at=NOW(),
       last_error=$5,
       follow_status=CASE
         WHEN $5 <> '' THEN 'error'
         WHEN regexp_replace(followed_version,'^[vV]','')=regexp_replace($2,'^[vV]','') AND $2 <> '' THEN 'followed'
         WHEN regexp_replace(ignored_version,'^[vV]','')=regexp_replace($2,'^[vV]','') AND $2 <> '' THEN 'ignored'
         WHEN regexp_replace(installed_version,'^[vV]','')=regexp_replace($2,'^[vV]','') AND $2 <> '' THEN 'current'
         WHEN $2 <> '' THEN 'update_available'
         ELSE 'unknown' END,
       updated_at=NOW()
     WHERE project_key=$1 RETURNING project_key`,
    [projectKey, release.version || '', release.releasedAt || null, release.url || '', release.error || '']
  );
  return result.rows[0] || null;
}

async function setMaintenanceProjectStatus(projectKey, action, actor = 'risk-admin') {
  if (!pool || !['followed', 'ignored', 'reset'].includes(action)) return null;
  const result = await pool.query(
    `UPDATE maintenance_projects SET
       follow_status=CASE WHEN $2='reset' THEN
         CASE WHEN latest_version <> '' AND regexp_replace(installed_version,'^[vV]','') <> regexp_replace(latest_version,'^[vV]','') THEN 'update_available' ELSE 'current' END
         ELSE $2 END,
       followed_version=CASE WHEN $2='followed' THEN latest_version WHEN $2='reset' THEN '' ELSE followed_version END,
       followed_at=CASE WHEN $2='followed' THEN NOW() WHEN $2='reset' THEN NULL ELSE followed_at END,
       ignored_version=CASE WHEN $2='ignored' THEN latest_version WHEN $2='reset' THEN '' ELSE ignored_version END,
       updated_at=NOW()
     WHERE project_key=$1
     RETURNING project_key,name,latest_version,follow_status,followed_at`,
    [projectKey, action]
  );
  if (!result.rows[0]) return null;
  await pool.query(
    `INSERT INTO admin_audits (actor,action,target,details)
     VALUES ($1,'set_maintenance_project_status',$2,$3::jsonb)`,
    [actor, projectKey, JSON.stringify({ action, version: result.rows[0].latest_version })]
  );
  const row = result.rows[0];
  return { projectKey: row.project_key, name: row.name, latestVersion: row.latest_version, followStatus: row.follow_status, followedAt: row.followed_at };
}

async function markMaintenanceProjectsAlerted(items) {
  if (!pool || !items.length) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const item of items) {
      await client.query(
        'UPDATE maintenance_projects SET alerted_version=$2,updated_at=NOW() WHERE project_key=$1',
        [item.projectKey, item.latestVersion]
      );
    }
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

async function createMaintenanceToken(actor = 'risk-admin', ttlMinutes = 15, maxUses = 50) {
  if (!pool) return null;
  await pool.query('DELETE FROM maintenance_tokens WHERE expires_at < NOW() - INTERVAL \'1 day\' OR revoked_at IS NOT NULL');
  const token = crypto.randomBytes(32).toString('base64url');
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const ttl = Math.max(5, Math.min(60, Number(ttlMinutes) || 15));
  const uses = Math.max(2, Math.min(100, Number(maxUses) || 50));
  const result = await pool.query(
    `INSERT INTO maintenance_tokens (token_hash,expires_at,max_uses,created_by)
     VALUES ($1,NOW()+($2::int * INTERVAL '1 minute'),$3,$4)
     RETURNING id,expires_at,max_uses`,
    [hash, ttl, uses, actor]
  );
  await pool.query(
    `INSERT INTO admin_audits (actor,action,target,details)
     VALUES ($1,'create_maintenance_read_token',$2,$3::jsonb)`,
    [actor, String(result.rows[0].id), JSON.stringify({ ttlMinutes: ttl, maxUses: uses })]
  );
  return { token, expiresAt: result.rows[0].expires_at, maxUses: Number(result.rows[0].max_uses) };
}

async function consumeMaintenanceToken(token) {
  if (!pool || !token || token.length < 32 || token.length > 200) return false;
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const result = await pool.query(
    `UPDATE maintenance_tokens SET use_count=use_count+1,last_used_at=NOW()
      WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>NOW() AND use_count<max_uses
      RETURNING id`, [hash]
  );
  return Boolean(result.rows[0]);
}

async function getMaintenanceSnapshot() {
  if (!pool) return null;
  const [overview, projects, migrations] = await Promise.all([
    getAdminOverview(),
    listMaintenanceProjects(),
    pool.query(`SELECT
      to_regclass('public.alert_settings') IS NOT NULL AS alerting,
      to_regclass('public.maintenance_projects') IS NOT NULL AS maintenance`)
  ]);
  return {
    generatedAt: new Date().toISOString(),
    service: { name: 'webring-bot-risk-center', version: require('../../package.json').version, nodeVersion: process.version, uptimeSeconds: Math.floor(process.uptime()) },
    database: { engine: 'postgresql', healthy: true, migrations: { alerting: Boolean(migrations.rows[0]?.alerting), maintenance: Boolean(migrations.rows[0]?.maintenance) } },
    redis: { healthy: Boolean(redis?.isReady) },
    overview,
    upstreams: projects.map(item => ({
      projectKey: item.projectKey, name: item.name, repository: item.repository,
      integrationMode: item.integrationMode, installedVersion: item.installedVersion,
      latestVersion: item.latestVersion, latestReleaseAt: item.latestReleaseAt,
      lastCheckedAt: item.lastCheckedAt, followStatus: item.followStatus,
      followedVersion: item.followedVersion, followedAt: item.followedAt,
      releaseUrl: item.releaseUrl, lastError: item.lastError
    }))
  };
}

async function claimNonce(clientId, nonce) {
  if (!redis) return true;
  const result = await redis.set(`risk:nonce:${clientId}:${nonce}`, '1', { NX: true, PX: 300_000 });
  return result === 'OK';
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
  applyManualControls,
  listDelta,
  evaluate,
  getSiteControl,
  authorizeClient,
  resolveClientAccess,
  markClientUsed,
  claimNonce,
  saveIntegration,
  rotateClientSecret,
  setClientEnabled,
  setSiteControls,
  getAdminOverview,
  listAdminSites,
  getRiskSummary,
  listSuspects,
  getSuspectDetail,
  applyManualDecision,
  clearManualDecision,
  listSignalRules,
  previewSignalRule,
  createSignalRule,
  setSignalRuleEnabled,
  deleteSignalRule,
  listAdminAudits,
  getAlertSettings,
  saveAlertSettings,
  listAlertCandidates,
  claimAlertNotifications,
  resolveRecoveredAlerts,
  recordAlertDelivery,
  listAlertActivity,
  listMaintenanceProjects,
  updateMaintenanceProject,
  setMaintenanceProjectStatus,
  markMaintenanceProjectsAlerted,
  createMaintenanceToken,
  consumeMaintenanceToken,
  getMaintenanceSnapshot,
  setSiteEnabled,
  close,
  isReady
};
