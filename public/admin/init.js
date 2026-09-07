/** 后台统一初始化、登录回调与 Hash 标签路由。 */
(() => {
  const token = () => localStorage.getItem('webring_admin_token') || '';
  const activeKey = 'admin_active_tab';
  const validTabs = new Set(['dashboard', 'partners', 'logs', 'categories', 'review', 'settings', 'ads', 'mirrors']);
  const aliases = { links: 'partners', 'inbound-logs': 'logs', audit: 'review' };
  const routes = { partners: 'links', logs: 'inbound-logs', review: 'audit' };
  const toast = message => { const el = document.querySelector('#toast'); if (!el) return; el.textContent = message; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 2400); };
  const normalizeTab = value => aliases[value] || value;

  /**
   * 审核与设置按钮由 review.js 动态挂载；在它们就绪后统一重排主导航，
   * 防止新增节点入口被追加到末尾而在窄屏中看似“丢失”。
   */
  function normalizePrimaryNavigation() {
    const tabs = document.querySelector('.tabs');
    if (!tabs) return;
    let mirrorLink = tabs.querySelector('[data-tab="mirrors"]');
    if (!mirrorLink) {
      mirrorLink = document.createElement('button');
      mirrorLink.type = 'button';
      mirrorLink.dataset.tab = 'mirrors';
      mirrorLink.textContent = '🌐 节点管理';
    }
    let logout = tabs.querySelector('#admin-logout');
    if (!logout) {
      logout = document.createElement('button');
      logout.id = 'admin-logout';
      logout.type = 'button';
      logout.className = 'admin-logout';
      logout.textContent = '退出登录';
      logout.onclick = () => {
        localStorage.removeItem('webring_admin_token');
        window.location.assign('/admin');
      };
    }

    const primary = [
      tabs.querySelector('[data-tab="dashboard"]'),
      tabs.querySelector('[data-tab="logs"]'),
      tabs.querySelector('[data-tab="categories"]'),
      document.querySelector('#review-tab'),
      tabs.querySelector('[data-tab="partners"]'),
      tabs.querySelector('[data-tab="ads"]'),
      mirrorLink,
      document.querySelector('#settings-tab'),
      logout
    ].filter(Boolean);
    // 清除旧内联脚本和动态模块留下的逐按钮 onclick，统一交给下方事件代理。
    primary.forEach(item => {
      if (item.matches?.('button[data-tab]')) item.onclick = null;
    });
    // 单页面后台的固定主导航顺序。
    tabs.replaceChildren(...primary);
  }

  async function loadTabData(tab) {
    if (!token()) return;
    if (tab === 'dashboard') return window.initAdminDashboard?.();
    if (tab === 'partners') return window.loadPartners?.();
    if (tab === 'logs') return window.loadLogs?.();
    if (tab === 'categories') return window.loadCategories?.();
    if (tab === 'review') return window.fetchPendingCount?.();
    if (tab === 'settings') return window.loadAdminSettings?.();
    if (tab === 'ads') return window.loadAdminAds?.();
    if (tab === 'mirrors') return window.loadAdminMirrors?.();
  }

  /** 切换面板，同时把可恢复状态写入 URL Hash 和 localStorage。 */
  window.switchAdminTab = function switchAdminTab(input, options = {}) {
    const tab = normalizeTab(input);
    if (!validTabs.has(tab)) return;
    document.querySelectorAll('.tabs button,.panel').forEach(item => item.classList.remove('active'));
    document.querySelector(`.tabs button[data-tab="${tab}"]`)?.classList.add('active');
    document.querySelector('#' + tab)?.classList.add('active');
    localStorage.setItem(activeKey, tab);
    const route = routes[tab] || tab;
    if (options.updateHash !== false && window.location.hash !== '#' + route) window.location.hash = route;
    Promise.resolve(loadTabData(tab)).catch(error => console.error('加载后台标签数据失败：', error));
  };

  /** 刷新或登录后恢复标签：Hash 优先，本地存储次之，最后才进入概览。 */
  window.restoreAdminTab = function restoreAdminTab() {
    const fromHash = normalizeTab(window.location.hash.replace(/^#/, ''));
    const fromStorage = normalizeTab(localStorage.getItem(activeKey) || '');
    const tab = validTabs.has(fromHash) ? fromHash : validTabs.has(fromStorage) ? fromStorage : 'dashboard';
    window.switchAdminTab(tab, { updateHash: !validTabs.has(fromHash) });
  };

  async function requestLogin(credentials) {
    const response = await fetch('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(credentials) });
    const result = await response.json(); if (result.code !== 200 || !result.data?.token) throw Error(result.msg || '登录失败'); return result.data.token;
  }
  async function handleLoginSuccess(newToken) {
    localStorage.setItem('webring_admin_token', newToken);
    document.querySelector('#login-modal')?.classList.remove('open');
    window.dispatchEvent(new Event('admin:authenticated'));
    window.restoreAdminTab();
    toast('登录成功，已恢复上次访问页面');
  }
  function bindTabs() {
    const tabs = document.querySelector('.tabs');
    if (!tabs || tabs.dataset.adminRouterBound === '1') return;
    tabs.dataset.adminRouterBound = '1';
    tabs.addEventListener('click', event => {
      const button = event.target.closest('button[data-tab]');
      if (!button || !tabs.contains(button)) return;
      event.preventDefault();
      window.switchAdminTab(button.dataset.tab);
    });
  }
  const form = document.querySelector('#login-form');
  if (form) form.onsubmit = async event => { event.preventDefault(); const submit = form.querySelector('button[type="submit"],button:not([type])'); try { if (submit) { submit.disabled = true; submit.textContent = '登录中…'; } await handleLoginSuccess(await requestLogin(Object.fromEntries(new FormData(form)))); } catch (error) { toast(error.message || '登录失败，请稍后重试'); } finally { if (submit) { submit.disabled = false; submit.textContent = '登录管理后台'; } } };
  window.addEventListener('hashchange', () => { const tab = normalizeTab(window.location.hash.replace(/^#/, '')); if (validTabs.has(tab)) window.switchAdminTab(tab, { updateHash: false }); });
  bindTabs();
  // review.js 在本文件之前创建审核/设置标签；赋予其路由标识并重新统一绑定。
  document.querySelector('#review-tab')?.setAttribute('data-tab', 'review'); document.querySelector('#settings-tab')?.setAttribute('data-tab', 'settings'); bindTabs();
  normalizePrimaryNavigation();
  bindTabs();
  if (token()) setTimeout(() => window.restoreAdminTab(), 0);
})();
