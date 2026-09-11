'use strict';

/** 可直接复制到无构建工具导航站后台的统一登录接收器。 */
(function installControlCenterSso(root) {
  async function consume(options = {}) {
    const locationApi = options.location || root.location;
    const historyApi = options.history || root.history;
    const storage = options.storage || root.localStorage;
    const fetchImpl = options.fetch || root.fetch.bind(root);
    const tokenKey = options.tokenKey || 'webring_admin_token';
    const match = /^#control-sso=([^&]+)$/.exec(locationApi.hash);
    if (!match) return false;

    historyApi.replaceState(null, '', `${locationApi.pathname}${locationApi.search}`);
    let code;
    try { code = decodeURIComponent(match[1]); }
    catch { throw new Error('统一登录交换码格式不合法'); }

    const response = await fetchImpl('/api/admin/control-center/session', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ code })
    });
    const payload = await response.json().catch(() => null);
    const token = payload?.data?.token;
    if (!response.ok || !token) throw new Error(payload?.message || payload?.msg || '统一登录交换失败，请返回总后台重试');
    storage.setItem(tokenKey, token);
    storage.setItem('webring_login_source', 'control_center');
    options.onSuccess?.(payload.data);
    return true;
  }

  root.ControlCenterSso = Object.freeze({ consume });
})(window);
