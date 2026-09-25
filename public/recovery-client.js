/** 正常访问时只同步恢复清单；不会测活候选域名，也不会查询 DoH。 */
(() => {
  const CORE_PATHS = new Set(['/api/links', '/api/showcase', '/api/config/public']);
  let consecutiveCoreFailures = 0;
  let recoveryTransitionStarted = false;
  const nativeFetch = window.fetch.bind(window);

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(error => console.warn('[Recovery] Service Worker 注册失败：', error.message)), { once: true });
  }

  async function syncVerifiedManifest() {
    try {
      const response = await nativeFetch('/api/recovery/manifest', { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) return;
      const payload = await response.json();
      const existing = await window.RecoveryCrypto.readState().catch(() => null);
      if (payload?.code !== 200) return;
      if (!payload.data?.enabled) {
        if (existing) await window.RecoveryCrypto.writeState({ ...existing, enabled: false, lastVerifiedAt: new Date().toISOString() });
        return;
      }
      await window.RecoveryCrypto.acceptManifest(payload.data, existing);
    } catch (error) { console.warn('[Recovery] 恢复清单同步失败：', error.message); }
  }

  function probeCurrentOrigin(timeoutMs = 3000) {
    return new Promise(resolve => {
      const image = new Image(); let settled = false;
      const finish = value => { if (settled) return; settled = true; clearTimeout(timer); image.onload = null; image.onerror = null; resolve(value); };
      const timer = setTimeout(() => { image.src = ''; finish(false); }, timeoutMs);
      image.onload = () => finish(image.naturalWidth === 1 && image.naturalHeight === 1);
      image.onerror = () => finish(false);
      image.src = `/.well-known/route-health.gif?recovery=${crypto.randomUUID()}&t=${Date.now()}`;
    });
  }

  async function confirmCoreFailure() {
    if (recoveryTransitionStarted || consecutiveCoreFailures < 2 || navigator.onLine === false) return;
    recoveryTransitionStarted = true;
    try {
      if (await probeCurrentOrigin()) { consecutiveCoreFailures = 0; recoveryTransitionStarted = false; return; }
      location.assign('/recovery.html?reason=core');
    } catch { recoveryTransitionStarted = false; }
  }

  window.fetch = async function recoveryAwareFetch(input, options) {
    const requestUrl = new URL(typeof input === 'string' ? input : input.url, location.href);
    const isCore = requestUrl.origin === location.origin && CORE_PATHS.has(requestUrl.pathname);
    try {
      const response = await nativeFetch(input, options);
      if (isCore && response.status >= 500) { consecutiveCoreFailures += 1; void confirmCoreFailure(); }
      else if (isCore && response.ok) consecutiveCoreFailures = 0;
      return response;
    } catch (error) {
      if (isCore) { consecutiveCoreFailures += 1; void confirmCoreFailure(); }
      throw error;
    }
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => void syncVerifiedManifest(), { once: true });
  else void syncVerifiedManifest();
})();
