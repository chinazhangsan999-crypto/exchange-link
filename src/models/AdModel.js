'use strict';

const { run, get, all, withTransaction } = require('../config/database');

const ACTIVE_TYPES = new Set(['normal', 'code']);
const ACTIVE_POSITIONS = new Set(['banner', 'icon', 'top_float', 'bottom_float', 'icon_float']);
const ACTIVE_PLATFORMS = new Set(['all', 'pc', 'ios', 'non_ios', 'android', 'harmony']);
const NORMAL_POSITIONS = new Set(['banner', 'icon']);
const CODE_POSITIONS = new Set(['top_float', 'bottom_float', 'icon_float']);

/**
 * 兼容迁移：旧库继续保留 type/description 等列，新业务统一使用
 * ad_type、ad_position 与 ad_code，避免重建大表造成启动锁库。
 */
async function initializeAdsTable() {
  await run(`CREATE TABLE IF NOT EXISTS ads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL DEFAULT 'banner' CHECK(type IN ('banner', 'icon')),
    title TEXT NOT NULL,
    ad_type TEXT NOT NULL DEFAULT 'normal',
    ad_position TEXT NOT NULL DEFAULT 'banner',
    platform TEXT NOT NULL DEFAULT 'all',
    ad_code TEXT DEFAULT '',
    target_url TEXT NOT NULL DEFAULT '',
    image_url TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 1 CHECK(status IN (0, 1)),
    description TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  const columns = await all('PRAGMA table_info(ads)');
  const names = new Set(columns.map(column => column.name));
  const additions = [
    ['ad_type', "TEXT NOT NULL DEFAULT 'normal'"],
    ['ad_position', "TEXT NOT NULL DEFAULT 'banner'"],
    ['platform', "TEXT NOT NULL DEFAULT 'all'"],
    ['ad_code', "TEXT DEFAULT ''"],
    ['description', "TEXT DEFAULT ''"],
    ['updated_at', 'DATETIME DEFAULT NULL']
  ];
  for (const [name, definition] of additions) {
    if (!names.has(name)) await run(`ALTER TABLE ads ADD COLUMN ${name} ${definition}`);
  }

  if (names.has('type') && (!names.has('ad_type') || !names.has('ad_position'))) {
    await run(`UPDATE ads
      SET ad_type = 'normal',
          ad_position = CASE WHEN type = 'icon' THEN 'icon' ELSE 'banner' END
      WHERE 1 = 1`);
  }
  await run("UPDATE ads SET ad_type = 'normal' WHERE ad_type IS NULL OR ad_type NOT IN ('normal', 'code')");
  // 把上一版的通用 normal 位置和不兼容组合平滑迁移到新分类。
  await run(`UPDATE ads SET ad_position = CASE
      WHEN ad_type = 'normal' AND type = 'icon' THEN 'icon'
      WHEN ad_type = 'normal' THEN 'banner'
      WHEN ad_type = 'code' AND ad_position IN ('top_float', 'bottom_float', 'icon_float') THEN ad_position
      ELSE 'top_float'
    END
    WHERE ad_position IS NULL
       OR ad_position = 'normal'
       OR ad_position NOT IN ('banner', 'icon', 'top_float', 'bottom_float', 'icon_float')
       OR (ad_type = 'normal' AND ad_position NOT IN ('banner', 'icon'))
       OR (ad_type = 'code' AND ad_position NOT IN ('top_float', 'bottom_float', 'icon_float'))`);
  await run("UPDATE ads SET platform = 'all' WHERE platform IS NULL OR platform NOT IN ('all', 'pc', 'ios', 'non_ios', 'android', 'harmony')");
  await run("UPDATE ads SET platform = 'all' WHERE ad_type = 'code'");
  await run("UPDATE ads SET ad_code = COALESCE(ad_code, ''), description = COALESCE(description, '')");
  await run("UPDATE ads SET ad_code = '' WHERE ad_type = 'normal'");
  await run("UPDATE ads SET image_url = '', target_url = '' WHERE ad_type = 'code'");
  await run('CREATE INDEX IF NOT EXISTS idx_ads_active_position_sort ON ads(status, ad_position, sort_order DESC, id ASC)');
}

function selectColumns() {
  return `id, title, ad_type, ad_position, platform, ad_code, target_url, image_url,
    sort_order, status, description, created_at, updated_at`;
}

function listAds() {
  return all(`SELECT ${selectColumns()} FROM ads ORDER BY sort_order DESC, id ASC`);
}

function getAdById(id) {
  return get(`SELECT ${selectColumns()} FROM ads WHERE id = ?`, [id]);
}

function getActiveAds() {
  return all(`SELECT id, title, ad_type, ad_position, platform, ad_code, target_url, image_url,
      sort_order, description
    FROM ads
    WHERE status = 1
    ORDER BY sort_order DESC, id ASC`);
}

function legacyTypeFor(item) {
  return item.adType === 'normal' && item.adPosition === 'icon' ? 'icon' : 'banner';
}

function createAd(item) {
  return run(`INSERT INTO ads(
      type, title, description, ad_type, ad_position, platform, ad_code,
      image_url, target_url, sort_order, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
    legacyTypeFor(item), item.title, item.description, item.adType, item.adPosition,
    item.platform, item.adCode, item.imageUrl, item.targetUrl, item.sortOrder, item.status
  ]);
}

function updateAd(id, item) {
  return run(`UPDATE ads
    SET type = ?, title = ?, description = ?, ad_type = ?, ad_position = ?,
        platform = ?, ad_code = ?, image_url = ?, target_url = ?,
        sort_order = ?, status = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?`, [
    legacyTypeFor(item), item.title, item.description, item.adType, item.adPosition,
    item.platform, item.adCode, item.imageUrl, item.targetUrl, item.sortOrder, item.status, id
  ]);
}

/** CSV 同步以“位置 + 标题”为业务键，兼容代码类型没有跳转 URL。 */
function syncAdsFromCsv(items) {
  return withTransaction(async ({ run: txRun, get: txGet }) => {
    let inserted = 0;
    let updated = 0;
    for (const item of items) {
      const existing = await txGet(
        'SELECT id FROM ads WHERE ad_position = ? AND title = ? LIMIT 1',
        [item.adPosition, item.title]
      );
      if (existing) {
        await txRun(`UPDATE ads
          SET type = ?, description = ?, ad_type = ?, platform = ?, ad_code = ?,
              image_url = ?, target_url = ?, sort_order = ?, status = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?`, [
          legacyTypeFor(item), item.description, item.adType, item.platform, item.adCode,
          item.imageUrl, item.targetUrl, item.sortOrder, item.status, existing.id
        ]);
        updated += 1;
      } else {
        await txRun(`INSERT INTO ads(
            type, title, description, ad_type, ad_position, platform, ad_code,
            image_url, target_url, sort_order, status
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
          legacyTypeFor(item), item.title, item.description, item.adType, item.adPosition,
          item.platform, item.adCode, item.imageUrl, item.targetUrl, item.sortOrder, item.status
        ]);
        inserted += 1;
      }
    }
    return { inserted, updated };
  });
}

function deleteAd(id) {
  return run('DELETE FROM ads WHERE id = ?', [id]);
}

function setAdStatus(id, status) {
  return run('UPDATE ads SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [status, id]);
}

/** 广告 CSV 是完整事实源；校验在事务开启前完成，事务内全量替换。 */
function replaceAdsFromCsv(items) {
  return withTransaction(async ({ run: txRun }) => {
    await txRun('DELETE FROM ads');
    for (const item of items) {
      await txRun(`INSERT INTO ads(
          type, title, description, ad_type, ad_position, platform, ad_code,
          image_url, target_url, sort_order, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
        legacyTypeFor(item), item.title, item.description, item.adType, item.adPosition,
        item.platform, item.adCode, item.imageUrl, item.targetUrl, item.sortOrder, item.status
      ]);
    }
    return { inserted: items.length, total: items.length };
  });
}

function listAdsForExport() {
  return all(`SELECT ad_type, ad_position, title, description, ad_code, image_url,
      target_url, sort_order, status
    FROM ads
    ORDER BY sort_order DESC, id ASC`);
}

module.exports = {
  ACTIVE_TYPES,
  ACTIVE_POSITIONS,
  ACTIVE_PLATFORMS,
  NORMAL_POSITIONS,
  CODE_POSITIONS,
  initializeAdsTable,
  listAds,
  getAdById,
  getActiveAds,
  createAd,
  updateAd,
  syncAdsFromCsv,
  replaceAdsFromCsv,
  listAdsForExport,
  deleteAd,
  setAdStatus
};
