'use strict';

const SLOTS = ['banner', 'icon', 'top_float', 'bottom_float', 'icon_float'];
const POLICIES = new Set(['central_only', 'central_first', 'mixed', 'local_only']);

function legacyType(ad) {
  return ad.ad_type === 'normal' && ad.ad_position === 'icon' ? 'icon' : 'banner';
}

function normalizeCentralAd(ad) {
  return {
    centralId: String(ad.id),
    namespace: String(ad.namespace || `central:${ad.id}`),
    type: legacyType(ad),
    title: String(ad.title || ''),
    description: String(ad.description || ''),
    adType: ad.ad_type,
    adPosition: ad.ad_position,
    platform: ad.platform || 'all',
    adCode: String(ad.ad_code || ''),
    imageUrl: String(ad.image_url || ''),
    targetUrl: String(ad.target_url || ''),
    sortOrder: Number(ad.priority || 0),
    integrity: String(ad.integrity_sha256 || '')
  };
}

function policyEntries(items = []) {
  const values = new Map(items.filter(item => SLOTS.includes(item.slot) && POLICIES.has(item.policy)).map(item => [item.slot, item.policy]));
  return SLOTS.map(slot => [`central_ad_policy:${slot}`, values.get(slot) || 'central_first']);
}

function adWeight(item) {
  const value = Number(item?.sort_order ?? item?.sortOrder ?? 0);
  return Number.isFinite(value) ? value : 0;
}

function stableAdSort(items) {
  return items.map((item, index) => ({ item, index })).sort((left, right) => adWeight(right.item) - adWeight(left.item) || left.index - right.index).map(entry => entry.item);
}

function selectAdsForSlot({ centralAds = [], localAds = [], policy = 'central_first' }) {
  const central = stableAdSort(centralAds);
  const local = stableAdSort(localAds);
  if (policy === 'central_only') return central;
  if (policy === 'local_only') return local;
  if (policy === 'mixed') return stableAdSort([...central, ...local]);
  return [...central, ...local];
}

async function ensureColumn(all, run, table, column, definition) {
  const columns = await all(`PRAGMA table_info(${table})`);
  if (!columns.some(item => item.name === column)) await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

function createWebringConfigApplier({ run, all, withTransaction, onChanged = async () => {} }) {
  if (![run, all, withTransaction].every(value => typeof value === 'function')) throw new Error('缺少导航站数据库适配函数');

  async function initialize() {
    await ensureColumn(all, run, 'mirrors', 'managed_by', "TEXT NOT NULL DEFAULT 'local'");
    await ensureColumn(all, run, 'mirrors', 'central_id', 'TEXT DEFAULT NULL');
    await ensureColumn(all, run, 'mirrors', 'sort_order', 'INTEGER NOT NULL DEFAULT 0');
    await run("UPDATE mirrors SET managed_by='local' WHERE managed_by='' OR managed_by IS NULL");
    await run("CREATE UNIQUE INDEX IF NOT EXISTS idx_mirrors_central_id ON mirrors(central_id) WHERE central_id IS NOT NULL");
    await ensureColumn(all, run, 'ads', 'managed_by', "TEXT NOT NULL DEFAULT 'local'");
    await ensureColumn(all, run, 'ads', 'central_id', 'TEXT DEFAULT NULL');
    await ensureColumn(all, run, 'ads', 'namespace', "TEXT NOT NULL DEFAULT ''");
    await ensureColumn(all, run, 'ads', 'integrity_sha256', "TEXT NOT NULL DEFAULT ''");
    await run("UPDATE ads SET managed_by='local', namespace='local:' || id WHERE namespace='' OR namespace IS NULL");
    await run("CREATE UNIQUE INDEX IF NOT EXISTS idx_ads_central_id ON ads(central_id) WHERE central_id IS NOT NULL");
  }

  async function applyConfig(config) {
    const nodes = Array.isArray(config?.nodes) ? config.nodes : [];
    const ads = Array.isArray(config?.ads) ? config.ads.map(normalizeCentralAd) : [];
    const settings = [
      ...policyEntries(config?.ad_policies),
      ['control_center_nodes_managed', '1'],
      ['control_center_revision', String(config?.revision || '')],
      ['publish_permanent_url', String(config?.publish?.permanent_url || '')],
      ['publish_github_pages_url', String(config?.publish?.github_pages_url || '')]
    ];
    await withTransaction(async ({ run: txRun, get: txGet }) => {
      await txRun("DELETE FROM mirrors WHERE managed_by='central'");
      for (const node of nodes) {
        const existing = await txGet('SELECT managed_by FROM mirrors WHERE url=?', [node.url]);
        // 节点由总后台作为唯一事实源；同 URL 的旧本地节点在首次接管时转为中央节点。
        if (existing && existing.managed_by !== 'central') await txRun('DELETE FROM mirrors WHERE url=?', [node.url]);
        await txRun(`INSERT INTO mirrors(speed_name,partner_name,url,status,managed_by,central_id,sort_order)
          VALUES(?,?,?,?,'central',?,?)`, [node.speed_name, node.partner_name, node.url, node.enabled === false ? 0 : 1, String(node.id), Number(node.sort_order || 0)]);
      }

      await txRun("DELETE FROM ads WHERE managed_by='central'");
      for (const ad of ads) {
        await txRun(`INSERT INTO ads(type,title,description,ad_type,ad_position,platform,ad_code,image_url,target_url,sort_order,status,managed_by,central_id,namespace,integrity_sha256)
          VALUES(?,?,?,?,?,?,?,?,?,?,1,'central',?,?,?)`, [ad.type,ad.title,ad.description,ad.adType,ad.adPosition,ad.platform,ad.adCode,ad.imageUrl,ad.targetUrl,ad.sortOrder,ad.centralId,ad.namespace,ad.integrity]);
      }

      for (const [key, value] of settings) {
        await txRun(`INSERT INTO site_configs(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP)
          ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`, [key, value]);
      }
    }, { priority: 'background', label: 'apply control center config', maxWaitMs: 120000, durability: 'full' });
    await onChanged(config);
    return { nodes: nodes.length, centralAds: ads.length, revision: config?.revision || '' };
  }

  return { initialize, applyConfig };
}

function consumeControlCenterSso({ request, storage = localStorage, historyApi = history, locationApi = location, tokenKey = 'webring_admin_token', onSuccess } = {}) {
  if (typeof request !== 'function') throw new Error('缺少统一登录会话交换函数');
  const match = /^#control-sso=([^&]+)$/.exec(locationApi.hash);
  if (!match) return Promise.resolve(false);
  historyApi.replaceState(null, '', `${locationApi.pathname}${locationApi.search}`);
  return request('/api/admin/control-center/session', { method: 'POST', body: { code: decodeURIComponent(match[1]) } })
    .then(result => {
      if (!result?.token) throw new Error('总后台登录交换失败');
      storage.setItem(tokenKey, result.token);
      storage.setItem('webring_login_source', 'control_center');
      onSuccess?.(result);
      return true;
    });
}

module.exports = { createWebringConfigApplier, normalizeCentralAd, policyEntries, selectAdsForSlot, consumeControlCenterSso };
