'use strict';

(() => {
  const hasSession = () => window.adminSessionActive === true;
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[char]));
  const notify = message => { const el = document.querySelector('#toast'); if (!el) return; el.textContent = message; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 2400); };
  let rows = [];

  async function request(url, options = {}) {
    const response = await fetch(url, { ...options, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
    const result = await response.json();
    if (!response.ok || result.code !== 200) throw new Error(result.msg || '请求失败');
    return result.data;
  }

  function ensureStyle() {
    if (!document.querySelector('link[href="/admin/ads.css"]')) {
      const link = document.createElement('link'); link.rel = 'stylesheet'; link.href = '/admin/ads.css'; document.head.append(link);
    }
    if (!document.querySelector('link[href="/admin/mirrors-tab.css"]')) {
      const link = document.createElement('link'); link.rel = 'stylesheet'; link.href = '/admin/mirrors-tab.css'; document.head.append(link);
    }
  }

  function ensureMirrorsNav() {
    // 主导航由 init.js 统一按 Hash Tab 顺序构建，避免跳转到独立节点页面。
  }

  let mirrorRows = [];
  const mirrorEndpoint = url => `/api/admin/mirrors/${encodeURIComponent(url)}`;

  /**
   * 节点表格统一事件代理：事件只绑定一次，后续重绘 tbody 不会重复注册。
   */
  function handleMirrorTableClick(event) {
    const button = event.target.closest('button');
    const body = event.currentTarget;
    if (!button || !body.contains(button)) return;

    const url = button.dataset.url || '';
    if (button.matches('.mirror-edit')) {
      event.preventDefault();
      const row = mirrorRows.find(item => item.url === url);
      if (row) openMirrorModal(row);
      return;
    }

    if (button.matches('.mirror-toggle')) {
      event.preventDefault();
      void toggleMirror(button);
      return;
    }

    if (button.matches('.mirror-delete')) {
      event.preventDefault();
      void deleteMirror(button);
    }
  }

  function ensureMirrorPanel() {
    if (document.querySelector('#mirrors')) return;
    const panel = document.createElement('section');
    panel.id = 'mirrors'; panel.className = 'panel';
    panel.innerHTML = `<div class="box mirror-admin-box"><div class="box-head"><div><h2>节点管理</h2><p class="hint">统一管理用于流量互换与霸榜的备用网址节点。</p></div><button id="open-mirror-modal" class="button" type="button">+ 新增节点</button></div><div class="table-wrap"><table class="mirror-admin-table"><thead><tr><th>测速名</th><th>友链霸榜名</th><th>节点地址</th><th>操作</th></tr></thead><tbody id="mirror-table-body"></tbody></table></div></div>`;
    const adsPanel = document.querySelector('#ads');
    adsPanel?.insertAdjacentElement('afterend', panel) || document.querySelector('.shell')?.append(panel);
    const addButton = panel.querySelector('#open-mirror-modal');
    const tableBody = panel.querySelector('#mirror-table-body');

    // 三类入口各自独立绑定，新增按钮明确传 null，禁止沿用任何编辑态数据。
    addButton.addEventListener('click', event => {
      event.preventDefault();
      event.stopPropagation();
      openMirrorModal(null);
    });
    tableBody.addEventListener('click', handleMirrorTableClick);
  }

  function renderMirrors() {
    const body = document.querySelector('#mirror-table-body'); if (!body) return;
    body.innerHTML = mirrorRows.map(row => `<tr><td><b>${esc(row.speed_name)}</b><small class="mirror-state ${Number(row.status) ? 'on' : 'off'}">${Number(row.status) ? '已启用' : '已停用'}</small></td><td>${esc(row.partner_name)}</td><td><a class="mirror-url" href="${esc(row.url)}" target="_blank" rel="noopener" title="${esc(row.url)}">${esc(row.url)}</a></td><td><div class="actions"><button type="button" class="action mirror-edit" data-url="${esc(row.url)}">编辑</button><button type="button" class="action mirror-toggle" data-url="${esc(row.url)}" data-status="${Number(row.status) ? 0 : 1}">${Number(row.status) ? '停用' : '启用'}</button><button type="button" class="action delete mirror-delete" data-url="${esc(row.url)}">删除</button></div></td></tr>`).join('') || '<tr><td colspan="4" class="hint">暂无节点。新增并启用后会自动同步为内部霸榜友链。</td></tr>';
  }

  async function loadMirrors() { if (!hasSession()) return; try { mirrorRows = await request('/api/admin/mirrors'); renderMirrors(); } catch (error) { notify(error.message); } }

  function openMirrorModal(row = null) {
    const originalUrl = row ? String(row.url || '') : '';
    let modal = document.querySelector('#mirror-modal');
    if (!modal) { modal = document.createElement('div'); modal.id = 'mirror-modal'; modal.className = 'modal'; document.body.append(modal); }
    modal.innerHTML = `<form id="mirror-form" class="dialog"><h3>${row ? '编辑节点' : '新增节点'}</h3><input name="original_url" type="hidden" value=""><div class="form-grid"><label class="full">测速名<input name="speed_name" maxlength="80" required value="${esc(row?.speed_name || '')}" placeholder="例如：华南高速线路"></label><label class="full">友链霸榜名<input name="partner_name" maxlength="80" required value="${esc(row?.partner_name || '')}" placeholder="例如：星环导航华南站"></label><label class="full">节点地址<input name="url" type="url" required value="${esc(row?.url || '')}" placeholder="https://node.example.com"></label><label>状态<select name="status"><option value="1" ${Number(row?.status ?? 1) === 1 ? 'selected' : ''}>启用</option><option value="0" ${Number(row?.status) === 0 ? 'selected' : ''}>停用</option></select></label></div><div class="dialog-foot"><button id="close-mirror-modal" type="button" class="button ghost">取消</button><button type="submit" class="button">保存节点</button></div></form>`;
    modal.classList.add('open');
    modal.querySelector('#close-mirror-modal').onclick = () => modal.classList.remove('open');
    modal.onclick = event => { if (event.target === modal) modal.classList.remove('open'); };
    const form = modal.querySelector('#mirror-form');
    // 新增时强制为空；编辑时仅写入当前记录 URL，防止复用上次弹窗状态。
    form.elements.original_url.value = originalUrl;
    form.onsubmit = null;
    form.onsubmit = saveMirror;
  }

  async function saveMirror(event) { event.preventDefault(); const form = event.currentTarget, data = Object.fromEntries(new FormData(form)), originalUrl = data.original_url; delete data.original_url; data.status = Number(data.status); try { await request(originalUrl ? mirrorEndpoint(originalUrl) : '/api/admin/mirrors', { method: originalUrl ? 'PUT' : 'POST', body: JSON.stringify(data) }); document.querySelector('#mirror-modal').classList.remove('open'); notify(originalUrl ? '节点已更新' : '节点已新增'); await loadMirrors(); } catch (error) { notify(error.message); } }
  async function toggleMirror(button) { try { await request(`${mirrorEndpoint(button.dataset.url)}/status`, { method: 'PATCH', body: JSON.stringify({ status: Number(button.dataset.status) }) }); notify(Number(button.dataset.status) ? '节点已启用' : '节点已停用'); await loadMirrors(); } catch (error) { notify(error.message); } }
  async function deleteMirror(button) { if (!confirm('确定删除该节点吗？对应内部霸榜友链也会同步移除。')) return; try { await request(mirrorEndpoint(button.dataset.url), { method: 'DELETE' }); notify('节点已删除'); await loadMirrors(); } catch (error) { notify(error.message); } }

  function ensureModal() {
    let modal = document.querySelector('#ad-modal');
    if (modal) return modal;
    modal = document.createElement('div'); modal.id = 'ad-modal'; modal.className = 'modal';
    modal.innerHTML = `<form id="ad-form" class="dialog dialog-wide"><h3 id="ad-form-title">新增广告</h3><input type="hidden" name="id"><div class="form-grid"><label>广告类型<select name="ad_type" required><option value="normal">普通图链</option><option value="code">代码联盟</option></select></label><label>广告位置<select name="ad_position" required><option value="banner" data-kind="normal">常规横幅</option><option value="icon" data-kind="normal">网格图标</option><option value="top_float" data-kind="code">顶部悬浮</option><option value="bottom_float" data-kind="code">底部悬浮</option><option value="icon_float" data-kind="code">图标悬浮</option></select></label><label class="platform-field">显示端<select name="platform" required><option value="all">全部显示</option><option value="pc">仅电脑端</option><option value="ios">仅 iOS 端</option><option value="non_ios">非 iOS 端</option><option value="android">仅安卓端</option><option value="harmony">仅鸿蒙端</option></select><span class="hint platform-note">仅普通图链支持设备定向</span></label><label>排序权重<input name="sort_order" type="number" min="0" max="999999" step="1" value="0" required></label><label class="full">广告标题<input name="title" maxlength="80" required placeholder="例如：合作品牌"></label><label class="full">广告介绍 <span class="hint">（选填）</span><textarea name="description" maxlength="300" placeholder="鼠标悬浮时显示；留空则不显示提示"></textarea></label><label class="full code-field">自定义代码 <span class="hint">（代码联盟必填，支持联盟提供的完整代码）</span><textarea name="ad_code" class="code-editor" placeholder="粘贴第三方 HTML 或 JavaScript 代码"></textarea></label><label class="full image-field">图片链接 <span class="hint">（普通图链必填）</span><input name="image_url" type="url" placeholder="https://example.com/image.jpg"></label><label class="full target-field">广告链接 <span class="hint">（普通图链必填）</span><input name="target_url" type="url" placeholder="https://example.com/"></label></div><div class="dialog-foot"><button id="close-ad-modal" type="button" class="button ghost">取消</button><button type="submit" class="button">保存广告</button></div></form>`;
    document.body.append(modal);
    modal.querySelector('#close-ad-modal').onclick = () => modal.classList.remove('open');
    modal.onclick = event => { if (event.target === modal) modal.classList.remove('open'); };
    const form = modal.querySelector('#ad-form');
    form.elements.ad_type.addEventListener('change', () => updateAdModeFields(form));
    form.onsubmit = saveAd;
    return modal;
  }

  function updateAdModeFields(form) {
    const isCode = form.elements.ad_type.value === 'code';
    const allowedKind = isCode ? 'code' : 'normal';
    const position = form.elements.ad_position;
    [...position.options].forEach(option => { option.disabled = option.dataset.kind !== allowedKind; });
    if (position.selectedOptions[0]?.disabled) position.value = isCode ? 'top_float' : 'banner';
    form.elements.platform.disabled = isCode;
    if (isCode) form.elements.platform.value = 'all';
    form.elements.ad_code.required = isCode;
    form.elements.image_url.required = !isCode;
    form.elements.target_url.required = !isCode;
    form.querySelector('.code-field')?.classList.toggle('is-required', isCode);
    form.querySelector('.code-field')?.classList.toggle('field-hidden', !isCode);
    form.querySelector('.image-field')?.classList.toggle('field-hidden', isCode);
    form.querySelector('.target-field')?.classList.toggle('field-hidden', isCode);
    form.querySelector('.platform-field')?.classList.toggle('field-disabled', isCode);
  }

  function openModal(ad = null) {
    const modal = ensureModal(), form = modal.querySelector('#ad-form'); form.reset();
    form.elements.id.value = ad?.id || ''; form.elements.ad_type.value = ad?.ad_type || 'normal'; form.elements.ad_position.value = ad?.ad_position || (ad?.ad_type === 'code' ? 'top_float' : 'banner'); form.elements.platform.value = ad?.platform || 'all'; form.elements.title.value = ad?.title || '';
    form.elements.description.value = ad?.description || ''; form.elements.ad_code.value = ad?.ad_code || ''; form.elements.image_url.value = ad?.image_url || ''; form.elements.target_url.value = ad?.target_url || ''; form.elements.sort_order.value = Number(ad?.sort_order || 0);
    updateAdModeFields(form);
    modal.querySelector('#ad-form-title').textContent = ad ? '编辑广告' : '新增广告'; modal.classList.add('open');
  }

  function render() {
    const body = document.querySelector('#ad-table-body'); if (!body) return;
    const typeName = { normal: '普通图链', code: '代码联盟' };
    const positionName = { banner: '常规横幅', icon: '网格图标', top_float: '顶部悬浮', bottom_float: '底部悬浮', icon_float: '图标悬浮' };
    const platformName = { all: '全部显示', pc: '仅电脑端', ios: '仅 iOS', non_ios: '非 iOS', android: '仅安卓', harmony: '仅鸿蒙' };
    body.innerHTML = rows.map(ad => `<tr><td class="ad-title-cell"><b title="${esc(ad.title)}">${esc(ad.title)}</b><small title="${esc(ad.description || '')}">${ad.ad_type === 'code' ? '已配置自定义代码' : (ad.description ? '已填写悬浮介绍' : '普通图链')}</small></td><td><span class="ad-type-pill ${esc(ad.ad_type)}">${typeName[ad.ad_type] || '普通图链'}</span></td><td><span class="ad-platform-pill">${positionName[ad.ad_position] || '—'}</span></td><td><span class="ad-platform-pill ${esc(ad.platform || 'all')}">${ad.ad_type === 'code' ? '全部显示' : (platformName[ad.platform] || '全部显示')}</span></td><td><b>${Number(ad.sort_order || 0)}</b></td><td><span class="tag ${Number(ad.status) ? 'ad-status-on' : 'ad-status-off'}">${Number(ad.status) ? '启用' : '停用'}</span></td><td>${ad.target_url ? `<a class="ad-target-cell" href="${esc(ad.target_url)}" target="_blank" rel="noopener" title="${esc(ad.target_url)}">${esc(ad.target_url)}</a>` : '<span class="hint">代码内定义</span>'}</td><td><div class="actions"><button type="button" class="action ad-edit" data-id="${ad.id}">编辑</button><button type="button" class="action ad-toggle" data-id="${ad.id}" data-status="${Number(ad.status) ? 0 : 1}">${Number(ad.status) ? '停用' : '启用'}</button><button type="button" class="action delete ad-delete" data-id="${ad.id}">删除</button></div></td></tr>`).join('') || '<tr><td colspan="8" class="hint">暂无广告；未配置时前台不会产生任何留白。</td></tr>';
    body.querySelectorAll('.ad-edit').forEach(button => button.onclick = () => openModal(rows.find(ad => Number(ad.id) === Number(button.dataset.id))));
    body.querySelectorAll('.ad-toggle').forEach(button => button.onclick = () => toggleAd(button));
    body.querySelectorAll('.ad-delete').forEach(button => button.onclick = () => removeAd(button));
  }

  async function loadAds() { if (!hasSession()) return; try { rows = await request('/api/admin/ads'); render(); } catch (error) { notify(error.message); } }
  async function saveAd(event) { event.preventDefault(); const form = event.currentTarget, data = Object.fromEntries(new FormData(form)); const id = data.id; delete data.id; data.sort_order = Number(data.sort_order); if (data.ad_type === 'code') data.platform = 'all'; const current = id ? rows.find(ad => Number(ad.id) === Number(id)) : null; data.status = current ? Number(current.status) : 1; try { await request(id ? `/api/admin/ads/${id}` : '/api/admin/ads', { method: id ? 'PUT' : 'POST', body: JSON.stringify(data) }); form.closest('.modal').classList.remove('open'); notify(id ? '广告已更新' : '广告已新增'); await loadAds(); } catch (error) { notify(error.message); } }
  async function toggleAd(button) { try { await request(`/api/admin/ads/${button.dataset.id}/status`, { method: 'PATCH', body: JSON.stringify({ status: Number(button.dataset.status) }) }); notify(Number(button.dataset.status) ? '广告已启用' : '广告已停用'); await loadAds(); } catch (error) { notify(error.message); } }
  async function removeAd(button) { if (!confirm('确定删除这条广告吗？')) return; try { await request(`/api/admin/ads/${button.dataset.id}`, { method: 'DELETE' }); notify('广告已删除'); await loadAds(); } catch (error) { notify(error.message); } }

  function ensureAdsTableStructure() {
    const table = document.querySelector('#ads table');
    if (!table) return;
    table.className = 'admin-ad-table';
    table.querySelector('thead').innerHTML = '<tr><th>广告标题</th><th>类型</th><th>位置</th><th>显示端</th><th>排序</th><th>状态</th><th>目标链接</th><th>操作</th></tr>';
  }

  ensureStyle(); ensureMirrorPanel(); ensureMirrorsNav(); ensureAdsTableStructure(); document.querySelector('#open-ad-modal')?.addEventListener('click', () => openModal());
  window.loadAdminAds = loadAds;
  window.loadAdminMirrors = loadMirrors;
})();
