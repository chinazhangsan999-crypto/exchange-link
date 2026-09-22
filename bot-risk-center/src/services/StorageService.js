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

const RISK_WINDOWS = Object.freeze({
  '24h': { key: '24h', label: '近 24 小时', interval: "NOW() - INTERVAL '24 hours'" },
  '7d': { key: '7d', label: '近 7 天', interval: "NOW() - INTERVAL '7 days'" },
  '30d': { key: '30d', label: '近 30 天', interval: "NOW() - INTERVAL '30 days'" },
  all: { key: 'all', label: '全部历史', interval: '' }
});

function resolveRiskWindow(value) {
  return RISK_WINDOWS[String(value || '').trim()] || RISK_WINDOWS['24h'];
}

function timeWindowClause(column, window) {
  return window.interval ? `AND ${column} >= ${window.interval}` : '';
}

function redisKey(siteKey, visitorHash) {
  return `risk:decision:${siteKey}:${visitorHash}`;
}

async function initialize() {
  if (ready) return;
  if (DATABASE_URL) {
    pool = new Pool({ connectionString: DATABASE_URL, max: 10, idleTimeoutMillis: 30_000 });
    for (const filename of ['001_initial.sql', '002_alerting.sql', '003_maintenance.sql', '004_agent_maintenance.sql', '005_analysis_drive.sql', '006_personal_drive_oauth.sql', '007_rule_telegram_backup.sql']) {
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
    return secret ? { ok: true, secret, clientId, siteKey, legacy: true, scopes: defaultClientScopes() } : { ok: false, reason: 'unknown_client' };
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
    return secret ? { ok: true, secret, clientId, siteKey, legacy: true, scopes: defaultClientScopes() } : { ok: false, reason: 'unknown_client' };
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
    enforcementMode: row.enforcement_mode || 'observe',
    scopes: normalizeScopes(row.scopes)
  };
}

function defaultClientScopes() {
  return ['risk.events.write', 'risk.decisions.read', 'risk.policy.read',
    'maintenance.inventory.write', 'maintenance.advisory.read', 'maintenance.test-result.write'];
}

function normalizeScopes(value) {
  const input = Array.isArray(value) ? value : [];
  return [...new Set(input.map(item => String(item || '').trim()).filter(Boolean))];
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

async function getAdminOverview(range = '24h') {
  const window = resolveRiskWindow(range);
  if (!pool) return { sites: 0, enabledSites: 0, events: 0, decisions: 0, range: window.key, rangeLabel: window.label };
  const result = await pool.query(
    `SELECT
       (SELECT COUNT(*)::int FROM sites) AS sites,
       (SELECT COUNT(*)::int FROM sites WHERE enabled) AS enabled_sites,
       (SELECT COUNT(*)::int FROM risk_events WHERE TRUE ${timeWindowClause('created_at', window)}) AS events,
       (SELECT COUNT(*)::int FROM risk_decisions WHERE TRUE ${timeWindowClause('created_at', window)}) AS decisions`
  );
  const row = result.rows[0] || {};
  return {
    sites: Number(row.sites) || 0,
    enabledSites: Number(row.enabled_sites) || 0,
    events: Number(row.events) || 0,
    decisions: Number(row.decisions) || 0,
    range: window.key,
    rangeLabel: window.label
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

async function getRiskSummary(siteKey = '', range = '24h') {
  const window = resolveRiskWindow(range);
  if (!pool) return { visitors: 0, suspects: 0, blocked: 0, challenged: 0, signals: [], range: window.key, rangeLabel: window.label };
  const params = siteKey ? [siteKey] : [];
  const siteFilter = siteKey ? 'AND site_key = $1' : '';
  const eventWindow = timeWindowClause('created_at', window);
  const [events, decisions, signals] = await Promise.all([
    pool.query(
      `SELECT COUNT(DISTINCT visitor_hash)::int AS visitors
         FROM risk_events WHERE TRUE ${eventWindow} ${siteFilter}`,
      params
    ),
    pool.query(
      `WITH latest AS (
         SELECT DISTINCT ON (site_key, subject_hash) score, decision
           FROM risk_decisions
          WHERE TRUE ${eventWindow} ${siteFilter}
          ORDER BY site_key, subject_hash, sequence DESC
       ) SELECT COUNT(*) FILTER (WHERE score >= 25)::int AS suspects,
                COUNT(*) FILTER (WHERE decision = 'deny')::int AS blocked,
                COUNT(*) FILTER (WHERE decision IN ('silent_challenge', 'strong_challenge'))::int AS challenged
           FROM latest`,
      params
    ),
    pool.query(
      `SELECT event_type, COUNT(*)::int AS count,
              COUNT(DISTINCT visitor_hash)::int AS visitors
         FROM risk_events WHERE TRUE ${eventWindow} ${siteFilter}
        GROUP BY event_type ORDER BY count DESC LIMIT 12`,
      params
    )
  ]);
  return {
    visitors: Number(events.rows[0]?.visitors) || 0,
    suspects: Number(decisions.rows[0]?.suspects) || 0,
    blocked: Number(decisions.rows[0]?.blocked) || 0,
    challenged: Number(decisions.rows[0]?.challenged) || 0,
    signals: signals.rows.map(row => ({ signal: row.event_type, count: Number(row.count), visitors: Number(row.visitors) })),
    range: window.key,
    rangeLabel: window.label
  };
}

async function listSuspects({ siteKey = '', page = 1, limit = 50, minScore = 25, range = '24h' } = {}) {
  if (!pool) return { page: 1, limit, total: 0, items: [] };
  const window = resolveRiskWindow(range);
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
       WHERE TRUE ${timeWindowClause('d.created_at', window)} AND d.score >= $1 ${siteClause}
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
                ${timeWindowClause('re.created_at', window)}
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
    range: window.key,
    rangeLabel: window.label,
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
    expiresAt: row.expires_at, createdBy: row.created_by,
    createdAt: row.created_at, updatedAt: row.updated_at
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

  if (settings.upstreamUpdateAlertEnabled) {
    const staleInventories = await pool.query(
      `SELECT s.site_key,s.name,i.reported_at
         FROM sites s LEFT JOIN site_runtime_inventory i ON i.site_key=s.site_key
        WHERE s.enabled=TRUE AND (i.reported_at < NOW()-INTERVAL '12 hours'
           OR (i.reported_at IS NULL AND s.created_at < NOW()-INTERVAL '12 hours'))`
    );
    for (const row of staleInventories.rows) candidates.push({
      key: `inventory_stale:${row.site_key}`, kind: 'inventory_stale', severity: 'high',
      siteKey: row.site_key, siteName: row.name, value: 1,
      details: { window: '12小时', reportedAt: row.reported_at || null }
    });

    const incompatible = await pool.query(
      `SELECT i.site_key,s.name,i.protocol_version FROM site_runtime_inventory i
         JOIN sites s ON s.site_key=i.site_key
        WHERE s.enabled=TRUE AND i.protocol_version<>'risk-agent-v1'`
    );
    for (const row of incompatible.rows) candidates.push({
      key: `protocol_mismatch:${row.site_key}`, kind: 'protocol_mismatch', severity: 'critical',
      siteKey: row.site_key, siteName: row.name, value: 1,
      details: { window: '当前清单', protocolVersion: row.protocol_version, expectedProtocol: 'risk-agent-v1' }
    });

    const updates = await pool.query(
      `SELECT a.site_key,s.name,COUNT(*)::int AS updates,
              string_agg(a.project_key||' '||a.installed_version||'→'||a.latest_version, ', ' ORDER BY a.project_key) AS versions
         FROM maintenance_advisories a JOIN sites s ON s.site_key=a.site_key
         JOIN maintenance_projects p ON p.project_key=a.project_key AND p.latest_version=a.latest_version
        WHERE a.status IN ('awaiting_assessment','test_failed')
        GROUP BY a.site_key,s.name`
    );
    for (const row of updates.rows) candidates.push({
      key: `site_update:${row.site_key}`, kind: 'site_update', severity: 'high',
      siteKey: row.site_key, siteName: row.name, value: Number(row.updates),
      details: { window: '当前部署', updates: Number(row.updates), versions: row.versions }
    });
  }
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

function cleanInventoryComponents(items) {
  return (Array.isArray(items) ? items : []).slice(0, 100).map(item => ({
    key: String(item?.key || '').trim().toLowerCase().slice(0, 64),
    packageVersion: String(item?.packageVersion || '').trim().slice(0, 120),
    assetVersion: String(item?.assetVersion || '').trim().slice(0, 120),
    assetSha256: /^[a-f0-9]{64}$/i.test(String(item?.assetSha256 || '')) ? String(item.assetSha256).toLowerCase() : ''
  })).filter(item => /^[a-z0-9_-]{2,64}$/.test(item.key));
}

function cleanCapabilities(items) {
  return [...new Set((Array.isArray(items) ? items : []).slice(0, 100)
    .map(item => String(item || '').trim().toLowerCase().slice(0, 64))
    .filter(item => /^[a-z0-9_-]{2,64}$/.test(item)))];
}

function validTimestamp(value) {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function advisoryTemplate(projectKey) {
  if (projectKey === 'botd') return {
    impactLevel: 'high',
    affectedFeatures: ['自动化浏览器识别', '静默 PoW 验证', 'botd_detected 风险信号', 'browser_automation_confirmed 风险信号'],
    recommendation: '先在测试环境核对 npm 依赖与浏览器静态资源版本一致，再以观察模式灰度，确认真人误判率没有上升后发布。',
    requiredTests: ['Windows Chrome', 'Android Chrome', 'iPhone Safari', '微信/QQ 内置浏览器', '隐私浏览器', 'Playwright/Selenium', 'BotD 加载失败降级'],
    rolloutStrategy: ['测试服务器', '观察模式', '小流量灰度', '比较误判率', '正式发布并验证']
  };
  return {
    impactLevel: 'review',
    affectedFeatures: ['机器人风险识别与请求防护'],
    recommendation: '先阅读上游变更并在测试环境验证兼容性，不要直接自动升级生产环境。',
    requiredTests: ['自动化测试', 'PC 浏览器', '移动端浏览器', '降级路径'],
    rolloutStrategy: ['测试环境', '人工评估', '灰度发布', '生产验证']
  };
}

async function refreshSiteAdvisories(client, siteKey, components) {
  const componentMap = new Map(components.map(item => [item.key, item]));
  const projects = await client.query(
    `SELECT project_key,latest_version FROM maintenance_projects
      WHERE latest_version <> '' ORDER BY project_key`
  );
  for (const project of projects.rows) {
    const component = componentMap.get(project.project_key);
    if (!component) continue;
    const installedVersion = component.assetVersion || component.packageVersion || '';
    const latestVersion = String(project.latest_version || '');
    if (!installedVersion || !latestVersion
      || installedVersion.replace(/^[vV]/, '') === latestVersion.replace(/^[vV]/, '')) continue;
    const template = advisoryTemplate(project.project_key);
    await client.query(
      `INSERT INTO maintenance_advisories
        (site_key,project_key,installed_version,latest_version,impact_level,
         affected_features,recommendation,required_tests,rollout_strategy,status)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8::jsonb,$9::jsonb,'awaiting_assessment')
       ON CONFLICT (site_key,project_key,latest_version) DO UPDATE SET
         installed_version=EXCLUDED.installed_version,
         impact_level=EXCLUDED.impact_level,
         affected_features=EXCLUDED.affected_features,
         recommendation=EXCLUDED.recommendation,
         required_tests=EXCLUDED.required_tests,
         rollout_strategy=EXCLUDED.rollout_strategy,
         generated_at=NOW()`,
      [siteKey, project.project_key, installedVersion, latestVersion, template.impactLevel,
        JSON.stringify(template.affectedFeatures), template.recommendation,
        JSON.stringify(template.requiredTests), JSON.stringify(template.rolloutStrategy)]
    );
  }
}

async function saveRuntimeInventory(input) {
  if (!pool) return null;
  const components = cleanInventoryComponents(input.components);
  const capabilities = cleanCapabilities(input.capabilities);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO site_runtime_inventory
        (site_key,client_id,schema_version,app_version,git_commit,node_version,
         protocol_version,components,capabilities,deployed_at,reported_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,NOW())
       ON CONFLICT (site_key) DO UPDATE SET
         client_id=EXCLUDED.client_id,schema_version=EXCLUDED.schema_version,
         app_version=EXCLUDED.app_version,git_commit=EXCLUDED.git_commit,
         node_version=EXCLUDED.node_version,protocol_version=EXCLUDED.protocol_version,
         components=EXCLUDED.components,capabilities=EXCLUDED.capabilities,
         deployed_at=EXCLUDED.deployed_at,reported_at=NOW()
       RETURNING site_key,client_id,reported_at`,
      [input.siteKey, input.clientId, input.schemaVersion, input.appVersion, input.gitCommit,
        input.nodeVersion, input.protocolVersion, JSON.stringify(components), JSON.stringify(capabilities),
        validTimestamp(input.deployedAt)]
    );
    await refreshSiteAdvisories(client, input.siteKey, components);
    await client.query('COMMIT');
    return { siteKey: result.rows[0].site_key, clientId: result.rows[0].client_id, reportedAt: result.rows[0].reported_at };
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

async function refreshAllSiteAdvisories() {
  if (!pool) return { refreshed: 0 };
  const result = await pool.query('SELECT site_key,components FROM site_runtime_inventory');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const row of result.rows) await refreshSiteAdvisories(client, row.site_key, cleanInventoryComponents(row.components));
    await client.query('COMMIT');
    return { refreshed: result.rows.length };
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

function mapAdvisory(row) {
  return {
    id: Number(row.id), siteKey: row.site_key, projectKey: row.project_key,
    projectName: row.project_name || row.project_key, installedVersion: row.installed_version,
    latestVersion: row.latest_version, impactLevel: row.impact_level,
    affectedFeatures: row.affected_features || [], recommendation: row.recommendation,
    requiredTests: row.required_tests || [], rolloutStrategy: row.rollout_strategy || [],
    status: row.status, generatedAt: row.generated_at, reviewedAt: row.reviewed_at
  };
}

async function listAgentAdvisories(siteKey) {
  if (!pool) return [];
  const result = await pool.query(
    `SELECT a.*,p.name AS project_name FROM maintenance_advisories a
       JOIN maintenance_projects p ON p.project_key=a.project_key
      WHERE a.site_key=$1 AND a.latest_version=p.latest_version
      ORDER BY a.generated_at DESC`, [siteKey]
  );
  return result.rows.map(mapAdvisory);
}

function cleanTestMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const output = {};
  for (const [rawKey, rawValue] of Object.entries(value).slice(0, 50)) {
    const key = String(rawKey || '').trim().slice(0, 64);
    if (!/^[a-z0-9_.-]{1,64}$/i.test(key) || /secret|token|password|cookie|authorization|environment/i.test(key)) continue;
    if (!['string', 'number', 'boolean'].includes(typeof rawValue)) continue;
    output[key] = typeof rawValue === 'string' ? rawValue.slice(0, 300) : rawValue;
  }
  return output;
}

async function saveMaintenanceTestResult(input) {
  if (!pool) return null;
  const automated = cleanTestMap(input.automated);
  const browsers = cleanTestMap(input.browsers);
  const delta = Number.isFinite(Number(input.falsePositiveDelta)) ? Number(input.falsePositiveDelta) : null;
  const result = await pool.query(
    `INSERT INTO maintenance_test_results
      (site_key,client_id,project_key,target_version,test_commit,automated,browsers,
       false_positive_delta,recommendation,passed,tested_at)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9,$10,$11)
     RETURNING id,site_key,project_key,target_version,passed,tested_at,reported_at`,
    [input.siteKey, input.clientId, input.projectKey, input.targetVersion, input.testCommit,
      JSON.stringify(automated), JSON.stringify(browsers), delta, input.recommendation,
      input.passed, validTimestamp(input.testedAt) || new Date().toISOString()]
  );
  await pool.query(
    `UPDATE maintenance_advisories SET status=$4,reviewed_at=NOW()
      WHERE site_key=$1 AND project_key=$2 AND latest_version=$3`,
    [input.siteKey, input.projectKey, input.targetVersion, input.passed ? 'test_passed' : 'test_failed']
  );
  const row = result.rows[0];
  return { id: Number(row.id), siteKey: row.site_key, projectKey: row.project_key,
    targetVersion: row.target_version, passed: Boolean(row.passed), testedAt: row.tested_at, reportedAt: row.reported_at };
}

async function listSiteMaintenanceMatrix() {
  if (!pool) return [];
  const result = await pool.query(
    `SELECT s.site_key,s.name,i.client_id,i.app_version,i.git_commit,i.node_version,
            i.protocol_version,i.components,i.capabilities,i.deployed_at,i.reported_at,
            COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.generated_at DESC)
              FROM (SELECT a.project_key,p.name AS project_name,a.installed_version,a.latest_version,
                           a.impact_level,a.affected_features,a.recommendation,a.required_tests,
                           a.rollout_strategy,a.status,a.generated_at,a.reviewed_at
                      FROM maintenance_advisories a JOIN maintenance_projects p ON p.project_key=a.project_key
                     WHERE a.site_key=s.site_key AND a.latest_version=p.latest_version) x),'[]'::jsonb) AS advisories,
            COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY t.tested_at DESC)
              FROM (SELECT project_key,target_version,test_commit,automated,browsers,passed,
                           false_positive_delta,recommendation,tested_at,reported_at
                      FROM maintenance_test_results WHERE site_key=s.site_key
                     ORDER BY tested_at DESC LIMIT 20) t),'[]'::jsonb) AS tests
       FROM sites s LEFT JOIN site_runtime_inventory i ON i.site_key=s.site_key
      ORDER BY s.name,s.site_key`
  );
  return result.rows.map(row => ({
    siteKey: row.site_key, siteName: row.name, clientId: row.client_id || '',
    appVersion: row.app_version || '', gitCommit: row.git_commit || '', nodeVersion: row.node_version || '',
    protocolVersion: row.protocol_version || '', components: row.components || [], capabilities: row.capabilities || [],
    deployedAt: row.deployed_at, reportedAt: row.reported_at,
    protocolCompatible: row.protocol_version === 'risk-agent-v1',
    stale: !row.reported_at || Date.now() - new Date(row.reported_at).getTime() > 12 * 60 * 60 * 1000,
    advisories: row.advisories || [], tests: row.tests || []
  }));
}

function cleanAnalysisScopes(scopes) {
  const allowed = new Set(['suspects:list', 'suspects:detail']);
  return [...new Set((Array.isArray(scopes) ? scopes : []).filter(scope => allowed.has(scope)))];
}

async function createAnalysisToken(input, actor = 'risk-admin') {
  if (!pool) return null;
  const availableSites = await pool.query('SELECT site_key FROM sites WHERE enabled=TRUE ORDER BY site_key');
  const validSites = new Set(availableSites.rows.map(row => row.site_key));
  const siteKeys = [...new Set((Array.isArray(input.siteKeys) ? input.siteKeys : []).map(String).filter(key => validSites.has(key)))];
  const scopes = cleanAnalysisScopes(input.scopes);
  if (!siteKeys.length || !scopes.length) throw Object.assign(new Error('分析令牌必须指定站点和权限'), { statusCode: 400 });
  await pool.query("DELETE FROM analysis_tokens WHERE expires_at < NOW() - INTERVAL '1 day' OR revoked_at IS NOT NULL");
  const token = crypto.randomBytes(32).toString('base64url');
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const ttl = Math.max(5, Math.min(30, Number(input.ttlMinutes) || 15));
  const uses = Math.max(1, Math.min(20, Number(input.maxUses) || 20));
  const result = await pool.query(
    `INSERT INTO analysis_tokens (token_hash,scopes,site_keys,expires_at,max_uses,created_by)
     VALUES ($1,$2::jsonb,$3::jsonb,NOW()+($4::int * INTERVAL '1 minute'),$5,$6)
     RETURNING id,expires_at,max_uses`,
    [hash, JSON.stringify(scopes), JSON.stringify(siteKeys), ttl, uses, actor]
  );
  await pool.query(
    `INSERT INTO admin_audits (actor,action,target,details)
     VALUES ($1,'create_analysis_read_token',$2,$3::jsonb)`,
    [actor, String(result.rows[0].id), JSON.stringify({ ttlMinutes: ttl, maxUses: uses, scopes, siteKeys })]
  );
  return { token, expiresAt: result.rows[0].expires_at, maxUses: Number(result.rows[0].max_uses), scopes, siteKeys };
}

async function consumeAnalysisToken(token, requiredScope) {
  if (!pool || !token || token.length < 32 || token.length > 200) return null;
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const result = await pool.query(
    `UPDATE analysis_tokens SET use_count=use_count+1,last_used_at=NOW()
      WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>NOW() AND use_count<max_uses
        AND scopes ? $2
      RETURNING id,scopes,site_keys,expires_at,max_uses,use_count`,
    [hash, requiredScope]
  );
  const row = result.rows[0];
  return row ? {
    tokenId: Number(row.id), scopes: row.scopes || [], siteKeys: row.site_keys || [],
    expiresAt: row.expires_at, remainingUses: Math.max(0, Number(row.max_uses) - Number(row.use_count))
  } : null;
}

function safeAnalysisSince(value) {
  const parsed = value ? new Date(value) : new Date(Date.now() - 24 * 60 * 60_000);
  const earliest = new Date(Date.now() - 90 * 24 * 60 * 60_000);
  if (Number.isNaN(parsed.getTime())) return new Date(Date.now() - 24 * 60 * 60_000);
  return parsed < earliest ? earliest : parsed;
}

async function listAnalysisSuspects(input = {}, allowedSiteKeys = []) {
  if (!pool) return { page: 1, limit: 50, total: 0, filters: {}, items: [] };
  const allowed = [...new Set((allowedSiteKeys || []).map(String))];
  if (!allowed.length) return { page: 1, limit: 50, total: 0, filters: {}, items: [] };
  const safePage = Math.max(1, Number(input.page) || 1);
  const safeLimit = Math.max(1, Math.min(100, Number(input.limit) || 50));
  const safeScore = Math.max(0, Math.min(100, Number(input.minScore) || 25));
  const since = safeAnalysisSince(input.since);
  const requestedSite = String(input.siteKey || '');
  const sites = requestedSite ? (allowed.includes(requestedSite) ? [requestedSite] : []) : allowed;
  if (!sites.length) return {
    page: safePage, limit: safeLimit, total: 0,
    filters: { siteKey: requestedSite, minScore: safeScore, since: since.toISOString() }, items: []
  };
  const params = [safeScore, since.toISOString(), sites];
  const base = `WITH latest AS (
      SELECT DISTINCT ON (d.site_key,d.subject_hash)
             d.site_key,d.subject_hash,d.score,d.decision,d.reasons,d.created_at,d.expires_at
        FROM risk_decisions d
       WHERE d.score >= $1 AND d.created_at >= $2::timestamptz AND d.site_key=ANY($3::text[])
       ORDER BY d.site_key,d.subject_hash,d.sequence DESC
    )`;
  const count = await pool.query(`${base} SELECT COUNT(*)::int AS total FROM latest`, params);
  const result = await pool.query(
    `${base}
     SELECT l.*,s.name AS site_name,COALESCE(e.event_count,0)::int AS event_count,
            e.first_seen,e.last_seen,e.signal_details,o.action AS manual_action,o.reason AS manual_reason
       FROM latest l JOIN sites s ON s.site_key=l.site_key
       LEFT JOIN LATERAL (
         SELECT COALESCE(SUM(re.signal_count),0)::int AS event_count,MIN(re.first_seen) AS first_seen,MAX(re.last_seen) AS last_seen,
                COALESCE(jsonb_agg(jsonb_build_object('signal',re.event_type,'count',re.signal_count,
                  'firstSeen',re.first_seen,'lastSeen',re.last_seen,'latestEvidence',re.latest_evidence)
                  ORDER BY re.signal_count DESC),'[]'::jsonb) AS signal_details
           FROM (
             SELECT event_type,COUNT(*)::int AS signal_count,MIN(occurred_at) AS first_seen,
                    MAX(occurred_at) AS last_seen,(ARRAY_AGG(evidence ORDER BY occurred_at DESC))[1] AS latest_evidence
               FROM risk_events WHERE site_key=l.site_key AND visitor_hash=l.subject_hash
                 AND created_at >= $2::timestamptz GROUP BY event_type
           ) re
       ) e ON TRUE
       LEFT JOIN manual_overrides o ON o.site_key=l.site_key AND o.visitor_hash=l.subject_hash
                                    AND (o.expires_at IS NULL OR o.expires_at>NOW())
      ORDER BY l.score DESC,l.created_at DESC OFFSET $4 LIMIT $5`,
    [...params, (safePage - 1) * safeLimit, safeLimit]
  );
  return {
    page: safePage, limit: safeLimit, total: Number(count.rows[0]?.total) || 0,
    filters: { siteKey: requestedSite && sites.length === 1 ? requestedSite : '', minScore: safeScore, since: since.toISOString() },
    items: result.rows.map(row => ({
      siteKey: row.site_key, siteName: row.site_name, visitorHash: row.subject_hash,
      score: Number(row.score), decision: row.decision, reasons: row.reasons || [],
      signals: (row.signal_details || []).map(detail => ({
        signal: detail.signal, count: Number(detail.count) || 0,
        scoreImpact: Number(SIGNAL_WEIGHTS[detail.signal] || 0), firstSeen: detail.firstSeen,
        lastSeen: detail.lastSeen, latestEvidence: detail.latestEvidence || {}
      })),
      eventCount: Number(row.event_count) || 0, firstSeen: row.first_seen, lastSeen: row.last_seen,
      decisionAt: row.created_at, expiresAt: row.expires_at,
      manualAction: row.manual_action || null, manualReason: row.manual_reason || null
    }))
  };
}

async function getGoogleDriveSettings({ includeCredentials = false } = {}) {
  if (!pool) return null;
  const result = await pool.query('SELECT * FROM google_drive_settings WHERE id=1');
  const row = result.rows[0];
  if (!row) return null;
  let credentials = null;
  let oauthClientSecret = null;
  let oauthRefreshToken = null;
  if (includeCredentials) {
    const secret = CredentialService.decrypt({ secret_ciphertext: row.credentials_ciphertext, secret_iv: row.credentials_iv, secret_tag: row.credentials_tag });
    if (secret) credentials = JSON.parse(secret);
    oauthClientSecret = CredentialService.decrypt({
      secret_ciphertext: row.oauth_client_secret_ciphertext,
      secret_iv: row.oauth_client_secret_iv,
      secret_tag: row.oauth_client_secret_tag
    });
    oauthRefreshToken = CredentialService.decrypt({
      secret_ciphertext: row.oauth_refresh_token_ciphertext,
      secret_iv: row.oauth_refresh_token_iv,
      secret_tag: row.oauth_refresh_token_tag
    });
  }
  const authMode = row.auth_mode || 'service_account';
  const personalConnected = Boolean(row.oauth_refresh_token_ciphertext && row.oauth_connected_email && row.oauth_folder_id);
  return {
    enabled: Boolean(row.enabled), folderId: row.folder_id, filePrefix: row.file_prefix,
    backupRange: row.backup_range, minScore: Number(row.min_score), siteKeys: row.site_keys || [],
    backupHourBjt: Number(row.backup_hour_bjt), authMode,
    configured: authMode === 'personal_oauth' ? personalConnected : Boolean(row.credentials_ciphertext),
    serviceAccountEmail: row.service_account_email, lastBackupAt: row.last_backup_at,
    lastFileId: row.last_file_id, lastError: row.last_error, credentials,
    oauthClientId: row.oauth_client_id || '',
    oauthClientConfigured: Boolean(row.oauth_client_id && row.oauth_client_secret_ciphertext),
    personalConnected,
    connectedEmail: row.oauth_connected_email || '',
    connectedAt: row.oauth_connected_at,
    personalFolderId: row.oauth_folder_id || '',
    personalFolderName: row.oauth_folder_name || '风险中心备份',
    personalFolderUrl: row.oauth_folder_id ? `https://drive.google.com/drive/folders/${encodeURIComponent(row.oauth_folder_id)}` : '',
    oauthClientSecret,
    oauthRefreshToken
  };
}

async function listEnabledSiteKeys() {
  if (!pool) return [];
  const result = await pool.query('SELECT site_key FROM sites WHERE enabled=TRUE ORDER BY site_key');
  return result.rows.map(row => row.site_key);
}

async function saveGoogleDriveSettings(input, actor = 'risk-admin') {
  if (!pool) return null;
  const enabled = input.enabled === true;
  const currentResult = await pool.query('SELECT oauth_client_id,folder_id FROM google_drive_settings WHERE id=1');
  const currentClientId = currentResult.rows[0]?.oauth_client_id || '';
  const folderId = input.folderId === undefined
    ? String(currentResult.rows[0]?.folder_id || '')
    : String(input.folderId || '').trim().slice(0, 200);
  const filePrefix = String(input.filePrefix || 'risk-center').trim().replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 80) || 'risk-center';
  const backupRange = ['24h', '7d', '30d'].includes(input.backupRange) ? input.backupRange : '7d';
  const parsedMinScore = Number(input.minScore);
  const parsedBackupHour = Number(input.backupHourBjt);
  const minScore = Math.max(0, Math.min(100, Number.isFinite(parsedMinScore) ? parsedMinScore : 25));
  const backupHourBjt = Math.max(0, Math.min(23, Number.isFinite(parsedBackupHour) ? parsedBackupHour : 3));
  const validSites = await pool.query('SELECT site_key FROM sites WHERE enabled=TRUE');
  const siteSet = new Set(validSites.rows.map(row => row.site_key));
  const siteKeys = [...new Set((input.siteKeys || []).map(String).filter(key => siteSet.has(key)))];
  const oauthClientId = String(input.oauthClientId || currentClientId).trim().slice(0, 300);
  if (oauthClientId && !/^[A-Za-z0-9._-]+\.apps\.googleusercontent\.com$/.test(oauthClientId)) {
    throw Object.assign(new Error('Google OAuth Client ID 格式无效'), { statusCode: 400 });
  }
  const oauthClientSecretInput = String(input.oauthClientSecret || '').trim();
  if (oauthClientSecretInput && (oauthClientSecretInput.length < 8 || oauthClientSecretInput.length > 500)) {
    throw Object.assign(new Error('Google OAuth Client Secret 格式无效'), { statusCode: 400 });
  }
  const oauthClientSecret = oauthClientSecretInput ? CredentialService.encrypt(oauthClientSecretInput) : null;
  const clientChanged = Boolean(currentClientId && oauthClientId !== currentClientId);
  if (clientChanged && !oauthClientSecretInput) {
    throw Object.assign(new Error('更换 OAuth Client ID 时必须同时填写新的 Client Secret'), { statusCode: 400 });
  }
  let credentials = null;
  if (String(input.credentialsJson || '').trim()) {
    try { credentials = JSON.parse(String(input.credentialsJson)); } catch { throw Object.assign(new Error('服务账号 JSON 格式无效'), { statusCode: 400 }); }
    if (credentials.type !== 'service_account' || !credentials.client_email || !credentials.private_key
      || credentials.token_uri !== 'https://oauth2.googleapis.com/token') {
      throw Object.assign(new Error('必须填写完整的 Google 服务账号 JSON'), { statusCode: 400 });
    }
  }
  const encrypted = credentials ? CredentialService.encrypt(JSON.stringify(credentials)) : null;
  await pool.query(
    `UPDATE google_drive_settings SET enabled=$1,folder_id=$2,file_prefix=$3,backup_range=$4,
       min_score=$5,site_keys=$6::jsonb,backup_hour_bjt=$7,
       credentials_ciphertext=COALESCE($8,credentials_ciphertext),credentials_iv=COALESCE($9,credentials_iv),
       credentials_tag=COALESCE($10,credentials_tag),service_account_email=COALESCE($11,service_account_email),
       updated_at=NOW() WHERE id=1`,
    [enabled, folderId, filePrefix, backupRange, minScore, JSON.stringify(siteKeys), backupHourBjt,
      encrypted?.ciphertext || null, encrypted?.iv || null, encrypted?.tag || null, credentials?.client_email || null]
  );
  await pool.query(
    `UPDATE google_drive_settings SET auth_mode='personal_oauth',oauth_client_id=$1,
       oauth_client_secret_ciphertext=COALESCE($2,oauth_client_secret_ciphertext),
       oauth_client_secret_iv=COALESCE($3,oauth_client_secret_iv),
       oauth_client_secret_tag=COALESCE($4,oauth_client_secret_tag),updated_at=NOW() WHERE id=1`,
    [oauthClientId, oauthClientSecret?.ciphertext || null, oauthClientSecret?.iv || null, oauthClientSecret?.tag || null]
  );
  if (clientChanged) {
    await pool.query(
      `UPDATE google_drive_settings SET oauth_refresh_token_ciphertext=NULL,oauth_refresh_token_iv=NULL,
         oauth_refresh_token_tag=NULL,oauth_connected_email='',oauth_connected_at=NULL,oauth_folder_id='',
         last_error='OAuth Client ID 已更改，请重新连接个人 Google Drive',updated_at=NOW() WHERE id=1`
    );
  }
  await pool.query(
    `INSERT INTO admin_audits (actor,action,target,details) VALUES ($1,'save_google_drive_settings','google-drive',$2::jsonb)`,
    [actor, JSON.stringify({ enabled, authMode: 'personal_oauth', oauthClientConfigured: Boolean(oauthClientId), oauthClientSecretUpdated: Boolean(oauthClientSecret), backupRange, minScore, siteKeys, backupHourBjt })]
  );
  return getGoogleDriveSettings();
}

async function createGoogleDriveOAuthState({ verifier, actor = 'risk-admin', ttlMinutes = 10 }) {
  if (!pool) return null;
  await pool.query('DELETE FROM google_drive_oauth_states WHERE expires_at < NOW()');
  const state = crypto.randomBytes(32).toString('base64url');
  const stateHash = crypto.createHash('sha256').update(state).digest('hex');
  const encrypted = CredentialService.encrypt(verifier);
  await pool.query(
    `INSERT INTO google_drive_oauth_states
       (state_hash,verifier_ciphertext,verifier_iv,verifier_tag,created_by,expires_at)
     VALUES ($1,$2,$3,$4,$5,NOW()+($6::int * INTERVAL '1 minute'))`,
    [stateHash, encrypted.ciphertext, encrypted.iv, encrypted.tag, actor, Math.max(5, Math.min(15, Number(ttlMinutes) || 10))]
  );
  return { state };
}

async function consumeGoogleDriveOAuthState(state) {
  if (!pool || !/^[A-Za-z0-9_-]{32,200}$/.test(String(state || ''))) return null;
  const stateHash = crypto.createHash('sha256').update(String(state)).digest('hex');
  const result = await pool.query(
    `DELETE FROM google_drive_oauth_states WHERE state_hash=$1 AND expires_at>NOW()
     RETURNING verifier_ciphertext,verifier_iv,verifier_tag,created_by`,
    [stateHash]
  );
  const row = result.rows[0];
  if (!row) return null;
  return {
    verifier: CredentialService.decrypt({
      secret_ciphertext: row.verifier_ciphertext,
      secret_iv: row.verifier_iv,
      secret_tag: row.verifier_tag
    }),
    actor: row.created_by
  };
}

async function saveGoogleDriveOAuthConnection({ refreshToken, email, folderId, folderName }, actor = 'risk-admin') {
  if (!pool || !refreshToken || !email || !folderId) throw new Error('Google Drive 个人账号连接信息不完整');
  const encrypted = CredentialService.encrypt(refreshToken);
  await pool.query(
    `UPDATE google_drive_settings SET auth_mode='personal_oauth',
       oauth_refresh_token_ciphertext=$1,oauth_refresh_token_iv=$2,oauth_refresh_token_tag=$3,
       oauth_connected_email=$4,oauth_connected_at=NOW(),oauth_folder_id=$5,oauth_folder_name=$6,
       last_error='',updated_at=NOW() WHERE id=1`,
    [encrypted.ciphertext, encrypted.iv, encrypted.tag, String(email).slice(0, 320), String(folderId).slice(0, 200), String(folderName || '风险中心备份').slice(0, 120)]
  );
  await pool.query(
    `INSERT INTO admin_audits (actor,action,target,details)
     VALUES ($1,'connect_personal_google_drive','google-drive',$2::jsonb)`,
    [actor, JSON.stringify({ email: String(email).slice(0, 320), folderId: String(folderId).slice(0, 200) })]
  );
  return getGoogleDriveSettings();
}

async function disconnectGoogleDriveOAuth(actor = 'risk-admin') {
  if (!pool) return null;
  await pool.query(
    `UPDATE google_drive_settings SET enabled=FALSE,oauth_refresh_token_ciphertext=NULL,
       oauth_refresh_token_iv=NULL,oauth_refresh_token_tag=NULL,oauth_connected_email='',
       oauth_connected_at=NULL,last_error='',updated_at=NOW() WHERE id=1`
  );
  await pool.query(
    `INSERT INTO admin_audits (actor,action,target,details)
     VALUES ($1,'disconnect_personal_google_drive','google-drive','{}'::jsonb)`,
    [actor]
  );
  return getGoogleDriveSettings();
}

async function recordGoogleDriveOAuthError(error) {
  if (!pool) return;
  await pool.query(
    'UPDATE google_drive_settings SET last_error=$1,updated_at=NOW() WHERE id=1',
    [String(error || '').slice(0, 1000)]
  );
}

async function recordGoogleDriveBackup(input) {
  if (!pool) return;
  await pool.query(
    `INSERT INTO google_drive_backup_runs (trigger_type,success,file_id,file_name,item_count,error,created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [input.triggerType, input.success, input.fileId || '', input.fileName || '', input.itemCount || 0, String(input.error || '').slice(0, 1000), input.createdBy || 'system']
  );
  await pool.query(
    `UPDATE google_drive_settings SET last_backup_at=CASE WHEN $1 THEN NOW() ELSE last_backup_at END,
       last_file_id=CASE WHEN $1 THEN $2 ELSE last_file_id END,last_error=$3,updated_at=NOW() WHERE id=1`,
    [input.success, input.fileId || '', input.success ? '' : String(input.error || '').slice(0, 1000)]
  );
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
  const [overview, projects, migrations, sites] = await Promise.all([
    getAdminOverview(),
    listMaintenanceProjects(),
    pool.query(`SELECT
      to_regclass('public.alert_settings') IS NOT NULL AS alerting,
      to_regclass('public.maintenance_projects') IS NOT NULL AS maintenance,
      to_regclass('public.site_runtime_inventory') IS NOT NULL AS agent_inventory`),
    listSiteMaintenanceMatrix()
  ]);
  return {
    generatedAt: new Date().toISOString(),
    service: { name: 'webring-bot-risk-center', version: require('../../package.json').version, nodeVersion: process.version, uptimeSeconds: Math.floor(process.uptime()) },
    database: { engine: 'postgresql', healthy: true, migrations: { alerting: Boolean(migrations.rows[0]?.alerting), maintenance: Boolean(migrations.rows[0]?.maintenance), agentInventory: Boolean(migrations.rows[0]?.agent_inventory) } },
    redis: { healthy: Boolean(redis?.isReady) },
    overview,
    sites,
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

async function getRuleBackupSettings({ includeSecrets = false } = {}) {
  if (!pool) return null;
  const result = await pool.query('SELECT * FROM rule_backup_settings WHERE id=1');
  const row = result.rows[0];
  if (!row) return null;
  const settings = {
    enabled: Boolean(row.enabled), automaticOnChange: Boolean(row.automatic_on_change),
    telegramChatId: row.telegram_chat_id || '', telegramConfigured: Boolean(row.telegram_token_ciphertext),
    backupHourBjt: Number(row.backup_hour_bjt), partSizeMiB: Number(row.part_size_mib),
    lastBackupAt: row.last_backup_at, lastContentSha256: row.last_content_sha256 || '',
    lastError: row.last_error || '', updatedAt: row.updated_at
  };
  if (includeSecrets) settings.telegramToken = CredentialService.decrypt({
    secret_ciphertext: row.telegram_token_ciphertext,
    secret_iv: row.telegram_token_iv,
    secret_tag: row.telegram_token_tag
  });
  return settings;
}

async function saveRuleBackupSettings(input, actor = 'risk-admin') {
  if (!pool) return null;
  const current = await getRuleBackupSettings({ includeSecrets: true });
  const token = String(input.telegramToken || '').trim() || current?.telegramToken || '';
  const encrypted = token ? CredentialService.encrypt(token) : null;
  const hourValue = Number(input.backupHourBjt);
  const partValue = Number(input.partSizeMiB);
  const backupHourBjt = Math.max(0, Math.min(23, Number.isFinite(hourValue) ? hourValue : 3));
  const partSizeMiB = Math.max(1, Math.min(18, Number.isFinite(partValue) ? partValue : 18));
  await pool.query(
    `UPDATE rule_backup_settings SET enabled=$1,automatic_on_change=$2,telegram_chat_id=$3,
       telegram_token_ciphertext=$4,telegram_token_iv=$5,telegram_token_tag=$6,
       backup_hour_bjt=$7,part_size_mib=$8,updated_at=NOW() WHERE id=1`,
    [input.enabled === true, input.automaticOnChange === true,
      String(input.telegramChatId || '').trim().slice(0, 100),
      encrypted?.ciphertext || null, encrypted?.iv || null, encrypted?.tag || null,
      backupHourBjt, partSizeMiB]
  );
  await pool.query(
    `INSERT INTO admin_audits (actor,action,target,details)
     VALUES ($1,'save_rule_backup_settings','rule-backup',$2::jsonb)`,
    [actor, JSON.stringify({ enabled: input.enabled === true, automaticOnChange: input.automaticOnChange === true,
      telegramConfigured: Boolean(token), backupHourBjt, partSizeMiB })]
  );
  return getRuleBackupSettings();
}

async function createRuleBackupRun(input) {
  if (!pool) return null;
  const encryptedKey = CredentialService.encrypt(input.backupKey);
  const result = await pool.query(
    `INSERT INTO rule_backup_runs
       (backup_id,trigger_type,status,rule_count,enabled_count,disabled_count,global_count,
        site_specific_count,content_sha256,parts_total,encrypted_payload,
        backup_key_ciphertext,backup_key_iv,backup_key_tag,created_by)
     VALUES ($1,$2,'uploading',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     RETURNING id,created_at`,
    [input.backupId, input.triggerType, input.summary.ruleCount, input.summary.enabledCount,
      input.summary.disabledCount, input.summary.globalCount, input.summary.siteSpecificCount,
      input.contentSha256, input.partsTotal, input.encryptedPayload,
      encryptedKey.ciphertext, encryptedKey.iv, encryptedKey.tag, input.createdBy || 'system']
  );
  return { id: Number(result.rows[0].id), createdAt: result.rows[0].created_at };
}

async function markRuleBackupPartUploaded(id, partNumber) {
  if (!pool) return;
  await pool.query(
    `UPDATE rule_backup_runs SET uploaded_parts=(
       SELECT COALESCE(jsonb_agg(value ORDER BY value), '[]'::jsonb)
       FROM (SELECT DISTINCT value FROM jsonb_array_elements(uploaded_parts || jsonb_build_array($2::int))) AS parts(value)
     ) WHERE id=$1`,
    [id, partNumber]
  );
}

async function finishRuleBackupRun(id, { contentSha256, summarySent = true } = {}) {
  if (!pool) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE rule_backup_runs SET status='success',summary_sent=$2,last_error='',completed_at=NOW(),
         next_retry_at=NULL,encrypted_payload=NULL,backup_key_ciphertext=NULL,backup_key_iv=NULL,backup_key_tag=NULL
       WHERE id=$1`,
      [id, summarySent === true]
    );
    await client.query(
      `UPDATE rule_backup_settings SET last_backup_at=NOW(),last_content_sha256=$1,last_error='',updated_at=NOW() WHERE id=1`,
      [contentSha256 || '']
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
}

async function failRuleBackupRun(id, error) {
  if (!pool) return;
  const message = String(error || '未知错误').slice(0, 2000);
  await Promise.all([
    pool.query(`UPDATE rule_backup_runs SET status='failed',last_error=$2,
      next_retry_at=NOW()+INTERVAL '15 minutes' WHERE id=$1`, [id, message]),
    pool.query('UPDATE rule_backup_settings SET last_error=$1,updated_at=NOW() WHERE id=1', [message])
  ]);
}

async function getRuleBackupRunForRetry() {
  if (!pool) return null;
  const result = await pool.query(
    `SELECT * FROM rule_backup_runs WHERE status='failed' AND encrypted_payload IS NOT NULL
      ORDER BY created_at DESC LIMIT 1`
  );
  const row = result.rows[0];
  if (!row) return null;
  return {
    id: Number(row.id), backupId: row.backup_id, triggerType: row.trigger_type,
    contentSha256: row.content_sha256, partsTotal: Number(row.parts_total),
    uploadedParts: (row.uploaded_parts || []).map(Number), summarySent: Boolean(row.summary_sent),
    encryptedPayload: Buffer.from(row.encrypted_payload),
    backupKey: CredentialService.decrypt({ secret_ciphertext: row.backup_key_ciphertext,
      secret_iv: row.backup_key_iv, secret_tag: row.backup_key_tag }),
    summary: { ruleCount: Number(row.rule_count), enabledCount: Number(row.enabled_count),
      disabledCount: Number(row.disabled_count), globalCount: Number(row.global_count),
      siteSpecificCount: Number(row.site_specific_count) }
  };
}

async function listRuleBackupRuns(limit = 20) {
  if (!pool) return [];
  const result = await pool.query(
    `SELECT backup_id,trigger_type,status,rule_count,enabled_count,disabled_count,global_count,
            site_specific_count,content_sha256,parts_total,uploaded_parts,summary_sent,last_error,
            created_by,created_at,completed_at,next_retry_at
       FROM rule_backup_runs ORDER BY created_at DESC LIMIT $1`,
    [Math.max(1, Math.min(100, Number(limit) || 20))]
  );
  return result.rows.map(row => ({
    backupId: row.backup_id, triggerType: row.trigger_type, status: row.status,
    ruleCount: Number(row.rule_count), enabledCount: Number(row.enabled_count),
    disabledCount: Number(row.disabled_count), globalCount: Number(row.global_count),
    siteSpecificCount: Number(row.site_specific_count), contentSha256: row.content_sha256,
    partsTotal: Number(row.parts_total), uploadedParts: (row.uploaded_parts || []).map(Number),
    summarySent: Boolean(row.summary_sent), lastError: row.last_error || '', createdBy: row.created_by,
    createdAt: row.created_at, completedAt: row.completed_at, nextRetryAt: row.next_retry_at
  }));
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
  saveRuntimeInventory,
  refreshAllSiteAdvisories,
  listAgentAdvisories,
  saveMaintenanceTestResult,
  listSiteMaintenanceMatrix,
  createAnalysisToken,
  consumeAnalysisToken,
  listAnalysisSuspects,
  getGoogleDriveSettings,
  saveGoogleDriveSettings,
  createGoogleDriveOAuthState,
  consumeGoogleDriveOAuthState,
  saveGoogleDriveOAuthConnection,
  disconnectGoogleDriveOAuth,
  recordGoogleDriveOAuthError,
  recordGoogleDriveBackup,
  listEnabledSiteKeys,
  createMaintenanceToken,
  consumeMaintenanceToken,
  getMaintenanceSnapshot,
  setSiteEnabled,
  getRuleBackupSettings,
  saveRuleBackupSettings,
  createRuleBackupRun,
  markRuleBackupPartUploaded,
  finishRuleBackupRun,
  failRuleBackupRun,
  getRuleBackupRunForRetry,
  listRuleBackupRuns,
  close,
  isReady
};
