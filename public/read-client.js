/** 公开展示数据的无感读取客户端：令牌仅驻留内存，过期或失配时自动续签一次。 */
(() => {
  'use strict';

  const REFRESHABLE_STATUS = new Set([401, 403, 428]);
  const EXPIRY_SAFETY_MS = 5000;
  const MAX_CONCURRENT_READS = 2;
  let accessToken = '';
  let accessExpiresAt = 0;
  let bootstrapPromise = null;
  const inFlightReads = new Map();
  const waitingReads = [];
  let activeReads = 0;

  function releaseReadSlot() {
    activeReads = Math.max(0, activeReads - 1);
    const next = waitingReads.shift();
    if (next) {
      activeReads += 1;
      next();
    }
  }

  function acquireReadSlot() {
    if (activeReads < MAX_CONCURRENT_READS) {
      activeReads += 1;
      return Promise.resolve();
    }
    return new Promise(resolve => waitingReads.push(resolve));
  }

  async function runWithReadSlot(task) {
    await acquireReadSlot();
    try { return await task(); }
    finally { releaseReadSlot(); }
  }

  function clearAccessToken() {
    accessToken = '';
    accessExpiresAt = 0;
  }

  async function requestAccessToken(forceRefresh = false) {
    if (forceRefresh) clearAccessToken();
    if (!forceRefresh && accessToken && Date.now() < accessExpiresAt - EXPIRY_SAFETY_MS) {
      return accessToken;
    }
    // 首页列表和精选内容会同时启动；所有调用共享同一个取证请求。
    if (bootstrapPromise) return bootstrapPromise;

    bootstrapPromise = fetch('/api/read/bootstrap', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    }).then(async response => {
      const result = await response.json().catch(() => null);
      if (!response.ok || result?.code !== 200 || !result.data?.token) {
        throw new Error(result?.msg || '获取读取凭证失败');
      }
      accessToken = String(result.data.token);
      accessExpiresAt = Number(result.data.expiresAt) || (Date.now() + 55000);
      return accessToken;
    }).finally(() => {
      bootstrapPromise = null;
    });
    return bootstrapPromise;
  }

  async function sendProtectedGet(input, init, token) {
    const headers = new Headers(init.headers || {});
    headers.set('X-Read-Token', token);
    if (!headers.has('Accept')) headers.set('Accept', 'application/json');
    return fetch(input, {
      ...init,
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      headers
    });
  }

  async function executeRead(input, init) {
    let response = await sendProtectedGet(input, init, await requestAccessToken());
    if (REFRESHABLE_STATUS.has(response.status)) {
      // 服务器重启、令牌到期或 Cookie 更新时只续签并重试一次，禁止无限重试。
      response = await sendProtectedGet(input, init, await requestAccessToken(true));
    }
    return response;
  }

  window.readApiFetch = function readApiFetch(input, init = {}) {
    const requestedMethod = String(init.method || 'GET').toUpperCase();
    if (requestedMethod !== 'GET') throw new TypeError('readApiFetch 仅用于受保护的只读 GET 接口');

    const canMerge = !init.signal && !init.headers;
    const requestKey = canMerge ? String(input) : '';
    if (requestKey && inFlightReads.has(requestKey)) {
      return inFlightReads.get(requestKey).then(response => response.clone());
    }

    const requestPromise = runWithReadSlot(() => executeRead(input, init));
    if (!requestKey) return requestPromise;
    inFlightReads.set(requestKey, requestPromise);
    requestPromise.finally(() => inFlightReads.delete(requestKey)).catch(() => {});
    return requestPromise.then(response => response.clone());
  };

  // defer 脚本按文档顺序执行；提前启动取证可与后续页面初始化重叠，减少骨架等待时间。
  window.readAccessReady = requestAccessToken().catch(() => null);
})();
