'use strict';

(() => {
  const loginView = document.getElementById('login-view');
  const dashboardView = document.getElementById('dashboard-view');
  const loginForm = document.getElementById('login-form');
  const loginButton = document.getElementById('login-button');
  const loginError = document.getElementById('login-error');
  const sitesBody = document.getElementById('sites-body');
  const refreshButton = document.getElementById('refresh-button');
  const logoutButton = document.getElementById('logout-button');
  const statusMessage = document.getElementById('status-message');
  let csrfToken = '';
  let toastTimer = null;

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    if (csrfToken && !['GET', 'HEAD'].includes(String(options.method || 'GET').toUpperCase())) {
      headers.set('X-CSRF-Token', csrfToken);
    }
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });
    const result = await response.json().catch(() => null);
    if (!response.ok) throw new Error(result?.message || `请求失败 (${response.status})`);
    return result;
  }

  function showToast(message) {
    clearTimeout(toastTimer);
    statusMessage.textContent = message;
    statusMessage.hidden = false;
    toastTimer = setTimeout(() => { statusMessage.hidden = true; }, 4000);
  }

  function setAuthenticated(authenticated) {
    loginView.hidden = authenticated;
    dashboardView.hidden = !authenticated;
    if (authenticated) refreshButton.focus();
  }

  function formatDate(value) {
    if (!value) return '尚未连接';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '未知' : new Intl.DateTimeFormat('zh-CN', {
      month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false
    }).format(date);
  }

  function cell(text, className = '') {
    const td = document.createElement('td');
    td.textContent = text;
    if (className) td.className = className;
    return td;
  }

  function renderSites(sites) {
    sitesBody.replaceChildren();
    if (!sites.length) {
      const row = document.createElement('tr');
      const empty = cell('尚无站点完成首次签名连接。', 'empty-cell');
      empty.colSpan = 7;
      row.append(empty);
      sitesBody.append(row);
      return;
    }

    for (const site of sites) {
      const row = document.createElement('tr');
      row.dataset.siteKey = site.siteKey;

      const nameCell = document.createElement('td');
      const name = document.createElement('span');
      name.className = 'site-name';
      name.textContent = site.name || site.siteKey;
      const key = document.createElement('span');
      key.className = 'site-key';
      key.textContent = site.siteKey;
      nameCell.append(name, key);

      const clientCell = document.createElement('td');
      const client = document.createElement('span');
      client.className = 'client-chip';
      client.textContent = site.clients?.map(item => item.clientId).join('、') || '未登记';
      clientCell.append(client);

      const statusCell = document.createElement('td');
      const status = document.createElement('span');
      status.className = `status-chip ${site.enabled ? 'on' : 'off'}`;
      status.textContent = site.enabled ? '已开启' : '已关闭';
      statusCell.append(status);

      const actionCell = document.createElement('td');
      actionCell.className = 'action-column';
      const action = document.createElement('button');
      action.type = 'button';
      action.className = `button ${site.enabled ? 'danger' : 'success'}`;
      action.dataset.action = 'toggle-site';
      action.dataset.enabled = String(site.enabled);
      action.textContent = site.enabled ? '关闭对接' : '开启对接';
      actionCell.append(action);

      row.append(
        nameCell,
        clientCell,
        cell(String(site.events24h || 0), 'numeric'),
        cell(String(site.decisions24h || 0), 'numeric'),
        cell(formatDate(site.lastUsedAt)),
        statusCell,
        actionCell
      );
      sitesBody.append(row);
    }
  }

  async function loadDashboard() {
    refreshButton.disabled = true;
    try {
      const [overview, sites] = await Promise.all([
        request('/admin/api/overview'),
        request('/admin/api/sites')
      ]);
      document.getElementById('metric-sites').textContent = overview.data.sites;
      document.getElementById('metric-enabled').textContent = overview.data.enabledSites;
      document.getElementById('metric-events').textContent = overview.data.events24h;
      document.getElementById('metric-decisions').textContent = overview.data.decisions24h;
      renderSites(sites.data || []);
    } finally {
      refreshButton.disabled = false;
    }
  }

  loginForm.addEventListener('submit', async event => {
    event.preventDefault();
    loginError.hidden = true;
    const formData = new FormData(loginForm);
    const username = String(formData.get('username') || '').trim();
    const password = String(formData.get('password') || '');
    if (!username || !password) {
      loginError.textContent = '请输入账号和密码。';
      loginError.hidden = false;
      return;
    }
    loginButton.disabled = true;
    loginButton.textContent = '正在登录…';
    try {
      const result = await request('/admin/api/login', {
        method: 'POST', body: JSON.stringify({ username, password })
      });
      csrfToken = result.data.csrfToken;
      loginForm.reset();
      setAuthenticated(true);
      await loadDashboard();
    } catch (error) {
      loginError.textContent = error.message;
      loginError.hidden = false;
    } finally {
      loginButton.disabled = false;
      loginButton.textContent = '安全登录';
    }
  });

  refreshButton.addEventListener('click', () => {
    loadDashboard().then(() => showToast('数据已刷新')).catch(error => showToast(error.message));
  });

  sitesBody.addEventListener('click', async event => {
    const button = event.target.closest('[data-action="toggle-site"]');
    if (!button) return;
    const row = button.closest('tr[data-site-key]');
    const siteKey = row?.dataset.siteKey;
    const enabled = button.dataset.enabled === 'true';
    if (!siteKey) return;
    if (enabled && !window.confirm(`确定关闭 ${siteKey} 与风险中心的对接吗？导航站本身仍会继续运行。`)) return;
    button.disabled = true;
    try {
      const result = await request(`/admin/api/sites/${encodeURIComponent(siteKey)}/status`, {
        method: 'PUT', body: JSON.stringify({ enabled: !enabled })
      });
      showToast(result.message);
      await loadDashboard();
    } catch (error) {
      button.disabled = false;
      showToast(error.message);
    }
  });

  logoutButton.addEventListener('click', async () => {
    logoutButton.disabled = true;
    try { await request('/admin/api/logout', { method: 'POST' }); }
    catch { /* 本地状态仍需立即清除。 */ }
    csrfToken = '';
    setAuthenticated(false);
    logoutButton.disabled = false;
  });

  request('/admin/api/session')
    .then(result => {
      csrfToken = result.data.csrfToken;
      setAuthenticated(true);
      return loadDashboard();
    })
    .catch(() => setAuthenticated(false));
})();
