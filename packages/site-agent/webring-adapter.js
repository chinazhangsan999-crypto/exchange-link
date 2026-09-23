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
    renderMode: ad.render_mode === 'sandbox' ? 'sandbox' : 'direct',
    sandboxOptions: ad.sandbox_options && typeof ad.sandbox_options === 'object' ? ad.sandbox_options : {},
    adEdgeProfileId: String(ad.ad_edge?.profile_id || ''),
    adEdgeOrigin: String(ad.ad_edge?.origin || ''),
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
    await run(`CREATE TABLE IF NOT EXISTS publish_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL CHECK(source IN ('local','control_center')),
      external_id TEXT DEFAULT NULL,
      label TEXT NOT NULL,
      url TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      sort_order INTEGER NOT NULL DEFAULT 0,
      sort_weight INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);
    await ensureColumn(all, run, 'publish_links', 'sort_weight', 'INTEGER NOT NULL DEFAULT 0');
    await run("CREATE UNIQUE INDEX IF NOT EXISTS idx_publish_links_central_id ON publish_links(external_id) WHERE source='control_center' AND external_id IS NOT NULL");
    const localPublishLinks = await all("SELECT id FROM publish_links WHERE source='local' LIMIT 1");
    if (!localPublishLinks.length) {
      const legacyPublishUrl = (await all("SELECT value FROM site_configs WHERE key='publish_url' LIMIT 1"))[0]?.value;
      if (legacyPublishUrl) {
        await run("INSERT INTO publish_links(source,label,url,enabled,sort_order,sort_weight) VALUES('local','本地永久发布页',?,1,0,0)", [legacyPublishUrl]);
      }
    }
    await ensureColumn(all, run, 'mirrors', 'managed_by', "TEXT NOT NULL DEFAULT 'local'");
    await ensureColumn(all, run, 'mirrors', 'central_id', 'TEXT DEFAULT NULL');
    await ensureColumn(all, run, 'mirrors', 'sort_order', 'INTEGER NOT NULL DEFAULT 0');
    await run("UPDATE mirrors SET managed_by='local' WHERE managed_by='' OR managed_by IS NULL");
    await run("CREATE UNIQUE INDEX IF NOT EXISTS idx_mirrors_central_id ON mirrors(central_id) WHERE central_id IS NOT NULL");
    await ensureColumn(all, run, 'ads', 'managed_by', "TEXT NOT NULL DEFAULT 'local'");
    await ensureColumn(all, run, 'ads', 'central_id', 'TEXT DEFAULT NULL');
    await ensureColumn(all, run, 'ads', 'namespace', "TEXT NOT NULL DEFAULT ''");
    await ensureColumn(all, run, 'ads', 'integrity_sha256', "TEXT NOT NULL DEFAULT ''");
    await ensureColumn(all, run, 'ads', 'render_mode', "TEXT NOT NULL DEFAULT 'direct'");
    await ensureColumn(all, run, 'ads', 'sandbox_options', "TEXT NOT NULL DEFAULT '{}'");
    await ensureColumn(all, run, 'ads', 'ad_edge_profile_id', "TEXT NOT NULL DEFAULT ''");
    await ensureColumn(all, run, 'ads', 'ad_edge_origin', "TEXT NOT NULL DEFAULT ''");
    await run("UPDATE ads SET managed_by='local', namespace='local:' || id WHERE namespace='' OR namespace IS NULL");
    await run("CREATE UNIQUE INDEX IF NOT EXISTS idx_ads_central_id ON ads(central_id) WHERE central_id IS NOT NULL");
  }

  async function applyConfig(config) {
    const nodes = Array.isArray(config?.nodes) ? config.nodes : [];
    const ads = Array.isArray(config?.ads) ? config.ads.map(normalizeCentralAd) : [];
    const publishPages = Array.isArray(config?.publish?.pages) ? config.publish.pages : [
      { id: 'cloudflare', label: 'Cloudflare 永久发布页', url: config?.publish?.permanent_url, sort_order: 10 },
      { id: 'github', label: 'GitHub Pages', url: config?.publish?.github_pages_url, sort_order: 20 }
    ].filter(item => item.url);
    const settings = [
      ...policyEntries(config?.ad_policies),
      ['control_center_nodes_managed', '1'],
      ['control_center_revision', String(config?.revision || '')],
      ['control_center_site_id', String(config?.site_id || '')],
      ['publish_permanent_url', String(config?.publish?.permanent_url || '')],
      ['publish_github_pages_url', String(config?.publish?.github_pages_url || '')],
      ['ad_edge_profile_id', String(config?.ad_edge?.profile_id || '')],
      ['ad_edge_origin', String(config?.ad_edge?.origin || '')],
      ['ad_edge_worker_version', String(config?.ad_edge?.worker_version || '')],
      ['ad_edge_ticket_key', String(config?.ad_edge?.ticket_key || '')],
      ['ad_edge_enabled', config?.ad_edge?.enabled === true ? '1' : '0']
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
        await txRun(`INSERT INTO ads(type,title,description,ad_type,ad_position,platform,ad_code,image_url,target_url,sort_order,status,managed_by,central_id,namespace,integrity_sha256,render_mode,sandbox_options,ad_edge_profile_id,ad_edge_origin)
          VALUES(?,?,?,?,?,?,?,?,?,?,1,'central',?,?,?,?,?,?,?)`, [ad.type,ad.title,ad.description,ad.adType,ad.adPosition,ad.platform,ad.adCode,ad.imageUrl,ad.targetUrl,ad.sortOrder,ad.centralId,ad.namespace,ad.integrity,ad.renderMode,JSON.stringify(ad.sandboxOptions),ad.adEdgeProfileId,ad.adEdgeOrigin]);
      }

      await txRun("DELETE FROM publish_links WHERE source='control_center'");
      for (const [index, page] of publishPages.entries()) {
        await txRun(`INSERT INTO publish_links(source,external_id,label,url,enabled,sort_order,sort_weight,updated_at)
          VALUES('control_center',?,?,?,?,?,?,CURRENT_TIMESTAMP)`, [String(page.id), String(page.label || `永久发布页 ${index + 1}`), page.url, page.enabled === false ? 0 : 1, Number(page.sort_order ?? index), Number(page.sort_weight ?? 0)]);
      }

      for (const [key, value] of settings) {
        await txRun(`INSERT INTO site_configs(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP)
          ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`, [key, value]);
      }
    }, { priority: 'background', label: 'apply control center config', maxWaitMs: 120000, durability: 'full' });
    await onChanged(config);
    return { nodes: nodes.length, centralAds: ads.length, centralPublishPages: publishPages.length, revision: config?.revision || '' };
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
