'use strict';

const { all, withTransaction } = require('../config/database');

function normalizePublishLink(item, index = 0) {
  const label = String(item?.label || '').trim().slice(0, 80);
  let url;
  try { url = new URL(String(item?.url || '').trim()); }
  catch { throw new Error(`第 ${index + 1} 个永久发布页地址格式不正确`); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error(`第 ${index + 1} 个永久发布页必须使用 HTTP 或 HTTPS 地址`);
  }
  return {
    label: label || `永久发布页 ${index + 1}`,
    url: url.href,
    enabled: item?.enabled === false ? 0 : 1,
    sortOrder: Number.isSafeInteger(Number(item?.sort_order)) ? Number(item.sort_order) : index,
    sortWeight: Number.isSafeInteger(Number(item?.sort_weight)) ? Number(item.sort_weight) : 0
  };
}

async function listAll() {
  return all(`SELECT id,source,external_id,label,url,enabled,sort_order,sort_weight,updated_at
    FROM publish_links
    ORDER BY sort_weight DESC,CASE source WHEN 'local' THEN 0 ELSE 1 END,sort_order ASC,id ASC`);
}

async function listPublic() {
  const rows = (await listAll()).filter(item => Number(item.enabled) === 1);
  const unique = new Map();
  for (const item of rows) {
    const key = String(item.url || '').toLowerCase();
    if (!key) continue;
    const current = unique.get(key);
    if (!current || (current.source !== 'local' && item.source === 'local')) unique.set(key, item);
  }
  return [...unique.values()].sort((left, right) =>
    Number(right.sort_weight || 0) - Number(left.sort_weight || 0)
    || (left.source === right.source ? 0 : left.source === 'local' ? -1 : 1)
    || Number(left.sort_order || 0) - Number(right.sort_order || 0)
    || Number(left.id || 0) - Number(right.id || 0)
  ).map(item => ({
    id: item.source === 'control_center' ? String(item.external_id || item.id) : `local:${item.id}`,
    label: item.label,
    url: item.url,
    source: item.source,
    sort_order: Number(item.sort_order || 0),
    sort_weight: Number(item.sort_weight || 0)
  }));
}

async function replaceLocal(items) {
  if (!Array.isArray(items)) throw new Error('本地永久发布页必须是列表');
  if (items.length > 30) throw new Error('本地永久发布页最多添加 30 条');
  const normalized = items.map(normalizePublishLink);
  const seen = new Set();
  for (const item of normalized) {
    const key = item.url.toLowerCase();
    if (seen.has(key)) throw new Error('本地永久发布页地址不能重复');
    seen.add(key);
  }
  await withTransaction(async ({ run }) => {
    await run("DELETE FROM publish_links WHERE source='local'");
    for (const item of normalized) {
      await run(`INSERT INTO publish_links(source,label,url,enabled,sort_order,sort_weight,updated_at)
        VALUES('local',?,?,?,?,?,CURRENT_TIMESTAMP)`, [item.label, item.url, item.enabled, item.sortOrder, item.sortWeight]);
    }
  }, { priority: 'interactive', label: 'save local publish links', durability: 'full' });
  return listAll();
}

module.exports = { listAll, listPublic, replaceLocal, normalizePublishLink };
