'use strict';

const crypto = require('crypto');
const { run, get, all, withTransaction } = require('../config/database');

const SID_PATTERN = /^[A-Za-z0-9_-]{32,128}$/;

function createSourceSid() {
  return crypto.randomBytes(32).toString('base64url');
}

function normalizeSourceSid(value) {
  const sid = String(value || '').trim();
  return SID_PATTERN.test(sid) ? sid : '';
}

async function insertPartnerSid(transaction, partnerId) {
  const existing = await transaction.get(`SELECT id, sid
    FROM partner_source_tokens
    WHERE default_partner_id = ? AND status = 1
    ORDER BY id DESC LIMIT 1`, [partnerId]);
  if (existing) return existing;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const sid = createSourceSid();
    try {
      const result = await transaction.run(`INSERT INTO partner_source_tokens(
        default_partner_id, sid, token_hint, status
      ) VALUES (?, ?, ?, 1)`, [partnerId, sid, sid.slice(-6)]);
      return { id: result.id, sid };
    } catch (error) {
      if (!/UNIQUE constraint failed/i.test(String(error?.message || '')) || attempt === 4) throw error;
    }
  }
  throw new Error('生成友链 SID 失败');
}

async function ensurePartnerSid(partnerId) {
  const id = Number(partnerId);
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error('友链编号不合法');
  return withTransaction(async transaction => {
    const partner = await transaction.get('SELECT id FROM partners WHERE id = ?', [id]);
    if (!partner) return null;
    return insertPartnerSid(transaction, id);
  }, { priority: 'interactive', label: 'ensure partner source sid', durability: 'full' });
}

async function ensureAllPartnersHaveSid() {
  return withTransaction(async transaction => {
    const partners = await transaction.all(`SELECT p.id
      FROM partners p
      LEFT JOIN partner_source_tokens token
        ON token.default_partner_id = p.id AND token.status = 1
      WHERE token.id IS NULL
      ORDER BY p.id ASC`);
    for (const partner of partners) await insertPartnerSid(transaction, partner.id);
    return { created: partners.length };
  }, { priority: 'background', label: 'backfill partner source sids', durability: 'full' });
}

async function findActiveSid(value) {
  const sid = normalizeSourceSid(value);
  if (!sid) return null;
  return get(`SELECT token.id AS token_id, token.sid,
      token.default_partner_id AS partner_id, partner.domain
    FROM partner_source_tokens token
    INNER JOIN partners partner ON partner.id = token.default_partner_id
    WHERE token.sid = ? AND token.status = 1
      AND partner.is_approved IN (0, 1)
    LIMIT 1`, [sid]);
}

async function initializeSourceTokenTables() {
  await run(`CREATE TABLE IF NOT EXISTS partner_source_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    default_partner_id INTEGER,
    sid TEXT NOT NULL UNIQUE COLLATE BINARY,
    token_hint TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 1,
    used_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    revoked_at DATETIME,
    FOREIGN KEY(default_partner_id) REFERENCES partners(id) ON DELETE SET NULL
  )`);
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_source_token_partner_active
    ON partner_source_tokens(default_partner_id)
    WHERE status = 1 AND default_partner_id IS NOT NULL`);
  await run('CREATE INDEX IF NOT EXISTS idx_source_token_sid_status ON partner_source_tokens(sid, status)');
  await ensureAllPartnersHaveSid();
}

function listPartnerSids() {
  return all(`SELECT id, default_partner_id, sid, token_hint, label, status,
      used_count, created_at, last_used_at, revoked_at
    FROM partner_source_tokens
    ORDER BY default_partner_id ASC, id ASC`);
}

module.exports = {
  SID_PATTERN,
  createSourceSid,
  normalizeSourceSid,
  insertPartnerSid,
  ensurePartnerSid,
  ensureAllPartnersHaveSid,
  findActiveSid,
  initializeSourceTokenTables,
  listPartnerSids
};
