'use strict';

const { run, get, all, withTransaction } = require('../config/database');

function normalizeMirrorUrl(value) {
  const parsed = new URL(String(value || '').trim());
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('节点地址仅支持 HTTP/HTTPS');
  parsed.hash = '';
  return parsed.href.replace(/\/$/, '');
}

function defaultName(url) {
  return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
}

function normalizeMirrorPayload(payload = {}) {
  const url = normalizeMirrorUrl(payload.url);
  const fallback = defaultName(url);
  const speedName = String(payload.speed_name ?? payload.speedName ?? '').trim() || fallback;
  const partnerName = String(payload.partner_name ?? payload.partnerName ?? '').trim() || speedName;
  const status = payload.status === undefined ? 1 : Number(payload.status);
  if (speedName.length > 80 || partnerName.length > 80) throw new Error('节点名称不能超过 80 个字符');
  if (![0, 1].includes(status)) throw new Error('节点状态不合法');
  return { speedName, partnerName, url, status, domain: fallback };
}

/**
 * mirrors 以 URL 作为唯一且稳定的业务主键。旧版本含自增 id / 探活字段时，
 * 通过临时表原子迁移，保留原 URL 和名称，之后不再依赖任何设置文本。
 */
async function initializeMirrorsTable() {
  const table = await get("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'mirrors'");
  if (!table) {
    await run(`CREATE TABLE mirrors (
      speed_name TEXT NOT NULL,
      partner_name TEXT NOT NULL,
      url TEXT PRIMARY KEY,
      status INTEGER NOT NULL DEFAULT 1 CHECK(status IN (0, 1))
    )`);
    await run('CREATE INDEX IF NOT EXISTS idx_mirrors_enabled ON mirrors(status, speed_name)');
    return;
  }

  const columns = await all('PRAGMA table_info(mirrors)');
  const isModern = columns.some(column => column.name === 'speed_name')
    && columns.some(column => column.name === 'partner_name')
    && columns.find(column => column.name === 'url')?.pk === 1
    && columns.some(column => column.name === 'status');
  if (!isModern) {
    await withTransaction(async ({ run: txRun }) => {
      await txRun(`CREATE TABLE mirrors_next (
        speed_name TEXT NOT NULL,
        partner_name TEXT NOT NULL,
        url TEXT PRIMARY KEY,
        status INTEGER NOT NULL DEFAULT 1 CHECK(status IN (0, 1))
      )`);
      // 旧表使用 name / online-offline 健康状态；迁移后 online 视为已启用。
      await txRun(`INSERT OR IGNORE INTO mirrors_next(speed_name, partner_name, url, status)
        SELECT
          COALESCE(NULLIF(TRIM(name), ''), url),
          COALESCE(NULLIF(TRIM(name), ''), url),
          url,
          CASE WHEN lower(COALESCE(status, 'online')) IN ('0', 'offline', 'disabled') THEN 0 ELSE 1 END
        FROM mirrors
        WHERE url IS NOT NULL AND TRIM(url) <> ''`);
      await txRun('DROP TABLE mirrors');
      await txRun('ALTER TABLE mirrors_next RENAME TO mirrors');
    });
  }
  await run('CREATE INDEX IF NOT EXISTS idx_mirrors_enabled ON mirrors(status, speed_name)');
}

function getAllMirrors() {
  return all('SELECT speed_name, partner_name, url, status FROM mirrors ORDER BY speed_name COLLATE NOCASE ASC, url ASC');
}

function getEnabledMirrors() {
  return all('SELECT speed_name, partner_name, url, status FROM mirrors WHERE status = 1 ORDER BY speed_name COLLATE NOCASE ASC, url ASC');
}

function getMirrorByUrl(url) {
  return get('SELECT speed_name, partner_name, url, status FROM mirrors WHERE url = ?', [normalizeMirrorUrl(url)]);
}

function createMirror(payload) {
  const mirror = normalizeMirrorPayload(payload);
  return run('INSERT INTO mirrors(speed_name, partner_name, url, status) VALUES (?, ?, ?, ?)', [mirror.speedName, mirror.partnerName, mirror.url, mirror.status]);
}

function updateMirror(originalUrl, payload) {
  const mirror = normalizeMirrorPayload(payload);
  return run(`UPDATE mirrors SET speed_name = ?, partner_name = ?, url = ?, status = ? WHERE url = ?`,
    [mirror.speedName, mirror.partnerName, mirror.url, mirror.status, normalizeMirrorUrl(originalUrl)]);
}

function setMirrorStatus(url, status) {
  const normalizedStatus = Number(status);
  if (![0, 1].includes(normalizedStatus)) throw new Error('节点状态不合法');
  return run('UPDATE mirrors SET status = ? WHERE url = ?', [normalizedStatus, normalizeMirrorUrl(url)]);
}

function deleteMirror(url) {
  return run('DELETE FROM mirrors WHERE url = ?', [normalizeMirrorUrl(url)]);
}

/** 节点 CSV 是完整事实源；事务内先清空再写入已经验证的节点。 */
async function replaceMirrorsFromCsv(rows) {
  const mirrors = rows.map(normalizeMirrorPayload);
  const seen = new Set();
  for (const mirror of mirrors) {
    if (seen.has(mirror.url)) throw new Error(`CSV 存在重复节点地址：${mirror.url}`);
    seen.add(mirror.url);
  }
  return withTransaction(async ({ run: txRun }) => {
    await txRun('DELETE FROM mirrors');
    for (const mirror of mirrors) {
      await txRun(
        'INSERT INTO mirrors(speed_name, partner_name, url, status) VALUES (?, ?, ?, ?)',
        [mirror.speedName, mirror.partnerName, mirror.url, mirror.status]
      );
    }
    return { inserted: mirrors.length, total: mirrors.length };
  }, { priority: 'background', label: 'replace mirrors from csv', maxWaitMs: 120000, durability: 'full' });
}

/** CSV 全量同步：当前 CSV 即节点事实源，未出现在 CSV 的旧节点会被移除。 */
async function syncMirrorsFromCsv(rows) {
  const mirrors = rows.map(normalizeMirrorPayload);
  const seen = new Set();
  for (const mirror of mirrors) {
    if (seen.has(mirror.url)) throw new Error(`CSV 存在重复节点地址：${mirror.url}`);
    seen.add(mirror.url);
  }
  return withTransaction(async ({ run: txRun, get: txGet }) => {
    await txRun('CREATE TEMP TABLE desired_mirror_urls(url TEXT PRIMARY KEY)');
    let inserted = 0;
    let updated = 0;
    for (const mirror of mirrors) {
      const existing = await txGet('SELECT url FROM mirrors WHERE url = ?', [mirror.url]);
      await txRun(`INSERT INTO mirrors(speed_name, partner_name, url, status)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(url) DO UPDATE SET
          speed_name = excluded.speed_name,
          partner_name = excluded.partner_name,
          status = excluded.status`, [mirror.speedName, mirror.partnerName, mirror.url, mirror.status]);
      if (existing) updated += 1;
      else inserted += 1;
      await txRun('INSERT INTO desired_mirror_urls(url) VALUES (?)', [mirror.url]);
    }
    const removed = await txRun(`DELETE FROM mirrors WHERE NOT EXISTS (
      SELECT 1 FROM desired_mirror_urls desired WHERE desired.url = mirrors.url
    )`);
    return { inserted, updated, deleted: removed.changes };
  }, { priority: 'background', label: 'sync mirrors from csv', maxWaitMs: 120000, durability: 'full' });
}

/**
 * 启用节点同步为内部矩阵友链；停用和删除节点会撤销对应内部友链。
 * 所有写入在同一事务内完成，保证节点与霸榜列表不会出现半同步状态。
 */
async function syncMirrorsToPartners() {
  return withTransaction(async ({ run: txRun, get: txGet, all: txAll }) => {
    const entries = await txAll('SELECT speed_name, partner_name, url FROM mirrors WHERE status = 1 ORDER BY speed_name COLLATE NOCASE ASC');
    const firstCategory = await txGet('SELECT name FROM categories ORDER BY sort_order ASC, id ASC LIMIT 1');
    if (entries.length && !firstCategory?.name) throw new Error('请先创建至少一个站点分类，再启用节点');

    await txRun('CREATE TEMP TABLE desired_internal_partner_ids(id INTEGER PRIMARY KEY)');
    let inserted = 0;
    let updated = 0;
    for (const entry of entries) {
      const url = normalizeMirrorUrl(entry.url);
      const domain = defaultName(url);
      const existing = await txGet('SELECT id FROM partners WHERE url = ? OR lower(domain) = lower(?) ORDER BY CASE WHEN url = ? THEN 0 ELSE 1 END LIMIT 1', [url, domain, url]);
      let partnerId;
      if (existing) {
        partnerId = existing.id;
        await txRun(`UPDATE partners SET name = ?, domain = ?, url = ?, category = ?, priority = 999,
          is_internal = 1, is_exempt = 1, is_approved = 1, backlink_status = 'valid', failed_check_count = 0,
          ping_status = 'ok', ping_failed_count = 0 WHERE id = ?`,
        [entry.partner_name, domain, url, firstCategory.name, partnerId]);
        updated += 1;
      } else {
        const result = await txRun(`INSERT INTO partners(name, domain, url, category, priority, is_internal, is_exempt, is_approved,
          backlink_status, failed_check_count, ping_status, ping_failed_count)
          VALUES (?, ?, ?, ?, 999, 1, 1, 1, 'valid', 0, 'ok', 0)`, [entry.partner_name, domain, url, firstCategory.name]);
        partnerId = result.id;
        inserted += 1;
      }
      await txRun('INSERT OR IGNORE INTO desired_internal_partner_ids(id) VALUES (?)', [partnerId]);
    }
    const deleted = await txRun(`DELETE FROM partners WHERE is_internal = 1 AND NOT EXISTS (
      SELECT 1 FROM desired_internal_partner_ids desired WHERE desired.id = partners.id
    )`);
    return { inserted, updated, deleted: deleted.changes };
  }, { priority: 'background', label: 'sync mirrors to partners', maxWaitMs: 120000, durability: 'full' });
}

module.exports = {
  initializeMirrorsTable,
  normalizeMirrorPayload,
  getAllMirrors,
  getEnabledMirrors,
  getMirrorByUrl,
  createMirror,
  updateMirror,
  setMirrorStatus,
  deleteMirror,
  replaceMirrorsFromCsv,
  syncMirrorsFromCsv,
  syncMirrorsToPartners
};
