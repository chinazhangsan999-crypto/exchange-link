/* 站点详情页：复用首页分类、配置和搜索入口，详情与推荐均读取真实公开数据。 */
(() => {
  const $ = (selector) => document.querySelector(selector);
  const colors = ['#2563eb', '#f59e0b', '#10b981', '#a855f7', '#ef4444', '#06b6d4'];
  const escapeHtml = (value) => String(value || '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
  const initials = (name) => String(name || '站点').trim().slice(0, 2).toUpperCase();
  let currentSiteUrl = '';
  let publicConfig = {};
  let currentSiteName = '';

  const detailDescription = $('#detailDescription');

  function showToast(message) { const toast = $('#detailToast'); toast.textContent = message; toast.classList.add('show'); clearTimeout(showToast.timer); showToast.timer = setTimeout(() => toast.classList.remove('show'), 1700); }
  async function copyText(value, message = '已复制到剪贴板') { if (!value) return; try { await navigator.clipboard.writeText(value); showToast(message); } catch { const field = document.createElement('textarea'); field.value = value; document.body.appendChild(field); field.select(); document.execCommand('copy'); field.remove(); showToast(message); } }
  function validUrl(value) { try { const url = new URL(String(value || '').trim()); return /^https?:$/.test(url.protocol) ? url.href : ''; } catch { return ''; } }

  // 与首页相同：只显示至少有一个已展示站点的活跃分类，并沿用后台排序。
  async function loadSidebarCategories() {
    const nav = $('#category-nav');
    try {
      const response = await fetch('/api/links', { credentials: 'same-origin' });
      const result = await response.json();
      if (result.code !== 200) throw new Error(result.msg || '获取友链数据失败');
      const sourceLinks = result.data?.links || [];
      const categoryMap = new Map((result.data?.categories || []).map(category => [category.name, category]));
      const categories = [...new Set(sourceLinks.map(link => link.category).filter(Boolean))]
        .map(name => categoryMap.get(name) || { id: `name-${encodeURIComponent(name)}`, name, sort_order: Number.MAX_SAFE_INTEGER })
        .sort((a, b) => (a.sort_order ?? Number.MAX_SAFE_INTEGER) - (b.sort_order ?? Number.MAX_SAFE_INTEGER) || String(a.name).localeCompare(String(b.name), 'zh-CN'));
      const icons = ['★', '◆', '▣', '✦', '◉', '◈'];
      nav.innerHTML = categories.map((category, index) => `
        <a href="/#category-${Number(category.id)}" title="${escapeHtml(category.name)}">
          <span class="nav-icon">${icons[index % icons.length]}</span><span>${escapeHtml(category.name)}</span>
        </a>`).join('') || '<span class="nav-loading">暂无分类</span>';
    } catch (error) { nav.innerHTML = '<span class="nav-loading">分类加载失败</span>'; console.warn('加载详情页分类失败：', error.message); }
  }

  function applySiteLogo(config) {
    const raw = String(config?.site_logo_url || '').trim();
    const logoUrl = validUrl(raw) || (/^\/uploads\/logo\/[a-zA-Z0-9._-]+$/.test(raw) ? raw : '');
    document.querySelectorAll('.brand-mark').forEach(mark => {
      mark.replaceChildren();
      if (!logoUrl) { mark.textContent = '✦'; return; }
      const image = new Image(); image.style.cssText = 'width:100%;height:100%;display:block;object-fit:contain;border-radius:inherit'; image.src = logoUrl; image.alt = '网站 Logo';
      image.onerror = () => { mark.replaceChildren(); mark.textContent = '✦'; };
      mark.append(image);
    });
    if (logoUrl) {
      const icon = document.querySelector('#runtime-site-favicon') || document.createElement('link');
      icon.id = 'runtime-site-favicon'; icon.rel = 'icon'; icon.href = `${logoUrl}${logoUrl.includes('?') ? '&' : '?'}favicon=1`;
      if (!icon.parentNode) document.head.append(icon);
    }
  }

  function renderRecommendations(items) {
    $('#hotExploreGrid').innerHTML = items.length ? items.map((item, index) => {
      const official = Number(item.priority) === 999;
      const href = official ? `/go?id=${Number(item.id)}` : `/site-detail.html?id=${Number(item.id)}`;
      return `
      <a href="${href}"${official ? ' target="_blank" rel="noopener"' : ''} class="explore-item" title="${escapeHtml(item.description || item.name)}">
        <span class="explore-item-left"><span class="item-avatar-mini" style="background:${colors[index % colors.length]}">${escapeHtml(initials(item.name))}</span><span class="item-info"><span class="item-title">${escapeHtml(item.name)}</span><span class="item-domain">${escapeHtml(item.domain)}</span></span></span>
      </a>`;
    }).join('') : '<div class="detail-state">暂未找到可推荐的其他站点</div>';
  }

  function renderSite(site, recommendations) {
    currentSiteUrl = site.url || '';
    currentSiteName = site.name || '';
    document.title = `${currentSiteName || '站点'} · 站点详情 · ${publicConfig.site_name || '星环导航'}`;
    $('#detailTitle').textContent = site.name || '未命名站点'; if (detailDescription) detailDescription.textContent = site.description || '该站点暂未填写简介。'; $('#btnVisit').href = `/go?id=${Number(site.id)}`;
    renderRecommendations(recommendations || []); $('#detailLoading').hidden = true; $('#detailContent').hidden = false;
  }
  async function loadDetail() { const id = Number(new URLSearchParams(location.search).get('id')); if (!Number.isSafeInteger(id) || id <= 0) throw new Error('站点编号无效'); const response = await fetch(`/api/links/${id}`, { credentials: 'same-origin' }); const result = await response.json(); if (!response.ok || result.code !== 200) throw new Error(result.msg || '站点不存在或暂不可用'); renderSite(result.data.site, result.data.recommendations); }
  /** 顶部框架与首页复用同一套节点，只由详情脚本绑定其数据和事件。 */
  async function loadPublicFrame() { const response = await fetch('/api/config/public', { credentials: 'same-origin' }); const result = await response.json(); if (result.code !== 200) return; publicConfig = result.data || {}; const siteName = String(publicConfig.site_name || '星环导航').trim() || '星环导航'; document.querySelectorAll('[data-site-name]').forEach(element => { element.textContent = siteName; }); applySiteLogo(publicConfig); document.querySelectorAll('[data-site-announcement]').forEach(element => { element.textContent = `✦ ${siteName}已收录审核通过的合作站点，排名随近 24 小时带量实时更新。`; }); document.title = currentSiteName ? `${currentSiteName} · 站点详情 · ${siteName}` : `站点详情 · ${siteName}`; const publishUrl = validUrl(publicConfig.publish_url); if (publishUrl) $('#topPublishBtn').href = publishUrl; }
  function searchHome() { const keyword = $('#site-search').value.trim(); location.href = `/${keyword ? `?q=${encodeURIComponent(keyword)}` : ''}`; }
  function initDrawer() { const sidebar = $('.sidebar'), overlay = $('#sidebarOverlay'), button = $('#mobileMenuBtn'); const close = () => { sidebar.classList.remove('open'); overlay.classList.remove('active'); button.setAttribute('aria-expanded', 'false'); }; button.onclick = () => { sidebar.classList.toggle('open'); overlay.classList.toggle('active'); button.setAttribute('aria-expanded', String(sidebar.classList.contains('open'))); }; overlay.onclick = close; $('#category-nav').onclick = close; document.addEventListener('keydown', (event) => { if (event.key === 'Escape') close(); }); }
  function initTheme() { const button = $('#themeToggle'); const apply = (theme) => { const dark = theme === 'dark'; document.documentElement.dataset.theme = dark ? 'dark' : 'light'; button.innerHTML = `${dark ? '🌙' : '☀️'} <span>${dark ? '夜间模式' : '日间模式'}</span>`; }; apply(localStorage.getItem('theme') || 'light'); button.onclick = () => { const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; localStorage.setItem('theme', next); apply(next); }; }
  function initModal() { const modal = $('#detailContactModal'); const close = () => { modal.hidden = true; }; $('#contactAdminBtn').onclick = () => { $('#detailContactContent').textContent = publicConfig.contact_info || publicConfig.admin_contact || '暂未配置站长联系方式。'; modal.hidden = false; }; modal.onclick = (event) => { if (event.target === modal) close(); }; modal.querySelector('.detail-modal-close').onclick = close; }
  function initPwa() { let promptEvent; const button = $('#pwa-install-btn'); window.addEventListener('beforeinstallprompt', (event) => { event.preventDefault(); promptEvent = event; button.style.display = 'inline-flex'; }); button.onclick = async () => { if (!promptEvent) return; promptEvent.prompt(); await promptEvent.userChoice; promptEvent = null; button.style.display = 'none'; }; }

  document.addEventListener('DOMContentLoaded', async () => {
    initDrawer(); initTheme(); initModal(); initPwa();
    $('#copyCurrentSiteUrl').onclick = () => copyText(currentSiteUrl, '站点链接已复制'); $('#applyLinkBtn').onclick = () => { sessionStorage.setItem('open_apply_modal', '1'); location.href = '/'; }; $('#search-button').onclick = searchHome; $('#site-search').onkeydown = (event) => { if (event.key === 'Enter') searchHome(); };
    try { await Promise.all([loadSidebarCategories(), loadPublicFrame(), loadDetail()]); } catch (error) { $('#detailLoading').textContent = error.message || '加载站点详情失败，请返回首页重试。'; }
  });
})();
