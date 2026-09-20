/** 后台统一初始化、登录回调与 Hash 标签路由。 */
(() => {
  /** SQLite UTC 文本统一转为北京时间，避免浏览器把无时区文本误当作本地时间。 */
  window.formatAdminTime = function formatAdminTime(value) {
    if (!value) return '—';
    const raw = String(value).trim();
    const normalized = raw.replace(' ', 'T');
    const source = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(normalized) ? normalized : `${normalized}Z`;
    const date = new Date(source);
    if (Number.isNaN(date.getTime())) return raw;
    return new Intl.DateTimeFormat('zh-CN', {
      timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    }).format(date).replace(/\//g, '-');
  };

  const hasSession = () => window.adminSessionActive === true;
  const activeKey = 'admin_active_tab';
  const validTabs = new Set(['dashboard', 'partners', 'logs', 'rejected-logs', 'categories', 'review', 'cloudflare', 'settings', 'ads', 'mirrors']);
  const aliases = { links: 'partners', 'inbound-logs': 'logs', 'unentered-logs': 'rejected-logs', audit: 'review' };
  const routes = { partners: 'links', logs: 'inbound-logs', 'rejected-logs': 'unentered-logs', review: 'audit' };
  const toast = message => { const el = document.querySelector('#toast'); if (!el) return; el.textContent = message; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 2400); };
  const normalizeTab = value => aliases[value] || value;

  /** 登录后读取系统设置，统一更新后台页签与品牌标题。 */
  window.loadAdminBrand = async function loadAdminBrand() {
    if (!hasSession()) return;
    try {
      const response = await fetch('/api/admin/settings');
      const result = await response.json();
      if (result.code !== 200) return;
      const siteName = String(result.data?.site_name || '').trim();
      const brand = siteName || '管理后台';
      const title = document.querySelector('.identity b');
      if (title) title.textContent = siteName ? `${siteName} · 管理中心` : '管理中心';
      const rawLogoUrl = String(result.data?.site_logo_url || '').trim();
      const logoUrl = /^https?:\/\//i.test(rawLogoUrl) || /^\/uploads\/logo\/[a-zA-Z0-9._-]+$/.test(rawLogoUrl) ? rawLogoUrl : '';
      const logo = document.querySelector('.identity .logo');
      if (logo) {
        logo.replaceChildren();
        if (!logoUrl) logo.textContent = '✦';
        else {
          const image = new Image();
          image.style.cssText = 'width:100%;height:100%;display:block;object-fit:contain;border-radius:inherit';
          image.src = logoUrl; image.alt = `${siteName || '网站'} Logo`;
          image.onerror = () => { logo.replaceChildren(); logo.textContent = '✦'; };
          logo.append(image);
          const icon = document.querySelector('#runtime-site-favicon') || document.createElement('link');
          icon.id = 'runtime-site-favicon'; icon.rel = 'icon'; icon.href = `${logoUrl}${logoUrl.includes('?') ? '&' : '?'}favicon=1`;
          if (!icon.parentNode) document.head.append(icon);
        }
      }
      document.title = `管理后台 · ${brand}`;
    } catch (error) {
      console.warn('加载后台品牌失败：', error);
    }
  };

  /**
   * 审核与设置按钮由 review.js 动态挂载；在它们就绪后统一重排主导航，
   * 防止新增节点入口被追加到末尾而在窄屏中看似“丢失”。
   */
  function normalizePrimaryNavigation() {
    const tabs = document.querySelector('.tabs');
    if (!tabs) return;
    let mirrorLink = tabs.querySelector('[data-tab="mirrors"]');
    if (window.controlCenterManaged) {
      mirrorLink?.remove();
      mirrorLink = null;
    } else if (!mirrorLink) {
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
      logout.onclick = async () => {
        try { await fetch('/api/admin/logout', { method: 'POST', credentials: 'same-origin' }); } catch {}
        window.adminSessionActive = false;
        window.location.assign('/admin');
      };
    }

    const primary = [
      tabs.querySelector('[data-tab="dashboard"]'),
      tabs.querySelector('[data-tab="logs"]'),
      tabs.querySelector('[data-tab="rejected-logs"]'),
      tabs.querySelector('[data-tab="categories"]'),
      document.querySelector('#review-tab'),
      tabs.querySelector('[data-tab="partners"]'),
      tabs.querySelector('[data-tab="ads"]'),
      mirrorLink,
      document.querySelector('#cloudflare-tab'),
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
    if (!hasSession()) return;
    if (tab === 'dashboard') return window.initDashboard?.();
    if (tab === 'partners') return Promise.all([
      Promise.resolve(window.loadPartners?.()),
      Promise.resolve(window.setupPartnerCategoryFilter?.())
    ]);
    if (tab === 'logs') return window.loadLogs?.();
    if (tab === 'rejected-logs') return window.loadRejectedLogs?.();
    if (tab === 'categories') return window.loadCategories?.();
    if (tab === 'review') return window.fetchPendingCount?.();
    if (tab === 'cloudflare') return window.loadCloudflareSettings?.();
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
    if (options.updateHash !== false && window.location.hash !== '#' + route) {
      history.replaceState(null, '', `${location.pathname}${location.search}#${route}`);
    }
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
    const result = await response.json(); if (result.code !== 200) throw Error(result.msg || '登录失败'); return true;
  }
  async function handleLoginSuccess() {
    window.adminSessionActive = true;
    document.querySelector('#login-modal')?.classList.remove('open');
    void window.loadAdminBrand();
    void window.refreshReviewCount?.();
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
  if (form) form.onsubmit = async event => { event.preventDefault(); const submit = form.querySelector('button[type="submit"],button:not([type])'); try { if (submit) { submit.disabled = true; submit.textContent = '登录中…'; } await requestLogin(Object.fromEntries(new FormData(form))); await handleLoginSuccess(); } catch (error) { toast(error.message || '登录失败，请稍后重试'); } finally { if (submit) { submit.disabled = false; submit.textContent = '登录管理后台'; } } };
  window.addEventListener('hashchange', () => { const tab = normalizeTab(window.location.hash.replace(/^#/, '')); if (validTabs.has(tab)) window.switchAdminTab(tab, { updateHash: false }); });
  bindTabs();
  // review.js 在本文件之前创建审核、Cloudflare 与设置标签；赋予其路由标识并重新统一绑定。
  document.querySelector('#review-tab')?.setAttribute('data-tab', 'review'); document.querySelector('#cloudflare-tab')?.setAttribute('data-tab', 'cloudflare'); document.querySelector('#settings-tab')?.setAttribute('data-tab', 'settings'); bindTabs();
  async function controlCenterStatus() {
    try {
      const response = await fetch('/api/admin/control-center/status', { credentials: 'same-origin' });
      const payload = await response.json();
      return payload?.data || { enabled: false };
    } catch { return { enabled: false }; }
  }

  async function consumeControlCenterSso() {
    const match = /^#control-sso=([^&]+)$/.exec(window.location.hash);
    if (!match) return false;
    history.replaceState(null, '', `${location.pathname}${location.search}`);
    let code;
    try { code = decodeURIComponent(match[1]); }
    catch { throw new Error('统一登录交换码格式不合法'); }
    const response = await fetch('/api/admin/control-center/session', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ code })
    });
    const payload = await response.json().catch(() => null);
    const newToken = payload?.data?.token;
    if (!response.ok || !newToken) throw new Error(payload?.message || payload?.msg || '统一登录交换失败，请返回总后台重试');
    const exchanged = await fetch('/api/admin/session/exchange', {
      method: 'POST', credentials: 'same-origin', headers: { Authorization: `Bearer ${newToken}` }
    });
    const exchangePayload = await exchanged.json().catch(() => null);
    if (!exchanged.ok || exchangePayload?.code !== 200) throw new Error(exchangePayload?.msg || '后台会话建立失败');

    // HttpOnly Cookie 由上一步响应设置，不能由脚本读取；必须立即用受保护接口
    // 验证它确实已被浏览器保存，不能把“交换成功”误当作“会话已可用”。
    const sessionResponse = await fetch('/api/admin/session', { credentials: 'same-origin' });
    const sessionPayload = await sessionResponse.json().catch(() => null);
    if (!sessionResponse.ok || sessionPayload?.code !== 200) {
      throw new Error(sessionPayload?.msg || '后台会话未能保存，请返回总后台重新进入');
    }
    window.adminSessionActive = true;
    return true;
  }

  function applyCentralManagementUi(status) {
    window.controlCenterManaged = status.enabled === true;
    if (!window.controlCenterManaged) return;
    document.querySelector('.tabs [data-tab="mirrors"]')?.remove();
    document.querySelector('#matrix-url-form [name="csv_url_mirrors"]')?.closest('label')?.remove();
    document.querySelectorAll('#matrix-url-form [data-sync-type="mirrors"]').forEach(item => item.remove());
    if (normalizeTab(window.location.hash.replace(/^#/, '')) === 'mirrors') {
      history.replaceState(null, '', `${location.pathname}#dashboard`);
    }

    if (!hasSession()) {
      const form = document.querySelector('#login-form');
      if (!form) return;
      form.replaceChildren();
      const title = document.createElement('h3');
      title.textContent = '统一后台登录';
      const hint = document.createElement('p');
      hint.className = 'hint login-hint';
      hint.textContent = '本站已关闭本地账号登录，请从总后台验证后进入。';
      const actions = document.createElement('div');
      actions.className = 'dialog-foot';
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'button';
      button.textContent = '前往总后台';
      button.onclick = () => window.location.assign(status.controlCenterUrl);
      actions.append(button);
      form.append(title, hint, actions);
    }
  }

  async function bootstrap() {
    try { await consumeControlCenterSso(); }
    catch (error) { toast(error.message || '统一登录失败，请返回总后台重试'); }
    const status = await controlCenterStatus();
    if (!window.adminSessionActive) {
      const session = await fetch('/api/admin/session', { credentials: 'same-origin' }).then(response => response.ok ? response.json() : null).catch(() => null);
      window.adminSessionActive = session?.code === 200;
    }
    applyCentralManagementUi(status);
    normalizePrimaryNavigation();
    bindTabs();
    if (hasSession()) {
      document.querySelector('#login-modal')?.classList.remove('open');
      void window.loadAdminBrand();
      void window.refreshReviewCount?.();
      window.restoreAdminTab();
    } else {
      document.querySelector('#login-modal')?.classList.add('open');
    }
  }

  void bootstrap();
})();
