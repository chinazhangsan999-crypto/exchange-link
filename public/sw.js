/** 星环导航离线恢复缓存：导航失败进入独立恢复页，敏感操作永不缓存。 */
const CACHE_NAME = 'nav-cache-v18-inline-recovery';
const RECOVERY_PAGE = '/recovery.html';
const RECOVERY_STYLE = '/recovery.css?v=20260921-recovery-1';
const RECOVERY_CRYPTO = '/recovery-crypto.js?v=20260922-recovery-shards-1';
const RECOVERY_SCRIPT = '/recovery.js?v=20260925-resolver-merge-1';
const STATIC_ASSETS = [
  '/', '/index.html', '/read-client.js?v=20260915-read-proof3', '/script.js?v=20260914-post-entry-page-view-all-pages', '/style.css', '/manifest.json',
  '/tooltip.css', '/apply.css', '/apply-category.css', '/no-icons.css',
  '/header-cleanup.css', '/mobile-nav.css', '/enhance.css', '/pwa.css',
  '/icons/icon-192.png', '/icons/icon-512.png',
  RECOVERY_STYLE,
  RECOVERY_CRYPTO, '/recovery-client.js?v=20260925-offline-recovery-1',
  RECOVERY_SCRIPT
];
const NEVER_CACHE_PATHS = new Set([
  '/verify.html', '/verify.css', '/verify.js', '/go', '/api/links/apply', '/api/read/bootstrap', '/api/read/proof'
]);

function escapeInlineScript(value) {
  return value.replace(/<\/script/gi, '<\\/script');
}

function buildInlineRecoveryPage(source, style, cryptoScript, recoveryScript, nonce) {
  let html = source
    .replace(/<link\b[^>]*href=["']\/recovery\.css[^"']*["'][^>]*>/i, `<style nonce="${nonce}">${style.replace(/<\/style/gi, '<\\/style')}</style>`)
    .replace(/<script\b[^>]*src=["']\/recovery-crypto\.js[^"']*["'][^>]*><\/script>/i, `<script nonce="${nonce}">${escapeInlineScript(cryptoScript)}</script>`)
    .replace(/<script\b[^>]*src=["']\/recovery\.js[^"']*["'][^>]*><\/script>/i, `<script nonce="${nonce}">${escapeInlineScript(recoveryScript)}</script>`)
    .replace(/<script\b[^>]*src=["']https:\/\/static\.cloudflareinsights\.com\/[^"']+["'][^>]*><\/script>/gi, '');
  if (!html.includes(`<style nonce="${nonce}">`) || (html.match(new RegExp(`nonce="${nonce}"`, 'g')) || []).length < 3) {
    throw new Error('恢复页内联资源构建失败');
  }
  return html;
}

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll(STATIC_ASSETS);
    const source = await fetch(RECOVERY_PAGE, { cache: 'no-store' });
    if (!source.ok) throw new Error(`恢复页预缓存失败：HTTP ${source.status}`);
    const [style, cryptoScript, recoveryScript] = await Promise.all([
      cache.match(RECOVERY_STYLE), cache.match(RECOVERY_CRYPTO), cache.match(RECOVERY_SCRIPT)
    ]);
    if (!style || !cryptoScript || !recoveryScript) throw new Error('恢复页预缓存资源不完整');
    const nonce = crypto.randomUUID().replace(/-/g, '');
    const html = buildInlineRecoveryPage(
      await source.text(), await style.text(), await cryptoScript.text(), await recoveryScript.text(), nonce
    );
    const headers = new Headers(source.headers);
    headers.delete('content-encoding');
    headers.delete('content-length');
    headers.delete('content-security-policy-report-only');
    headers.set('content-security-policy', `default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; img-src https: data:; connect-src https:`);
    headers.set('referrer-policy', 'no-referrer');
    const recovery = new Response(html, { status: 200, headers });
    await cache.put(RECOVERY_PAGE, recovery);
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});

function mustUseNetwork(url) {
  return NEVER_CACHE_PATHS.has(url.pathname)
    || url.pathname === '/.well-known/route-health.gif'
    || url.pathname === '/api/recovery/manifest'
    || url.pathname.startsWith('/api/verify/');
}

function isSafeCacheResponse(response) {
  if (!response || response.status !== 200 || response.redirected || response.type === 'opaqueredirect') return false;
  try { return new URL(response.url).pathname !== '/verify.html'; }
  catch { return false; }
}

function isCacheableRequest(request, url) {
  return url.origin === self.location.origin
    && !url.pathname.startsWith('/api/')
    && (request.mode === 'navigate' || /\.(?:html|css|js|png|jpe?g|gif|webp|svg|ico|woff2?|ttf)$/i.test(url.pathname));
}

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (mustUseNetwork(url)) {
    event.respondWith(fetch(event.request));
    return;
  }
  if (!isCacheableRequest(event.request, url)) {
    event.respondWith(fetch(event.request));
    return;
  }

  event.respondWith((async () => {
    try {
      const response = await fetch(event.request);
      if (event.request.mode === 'navigate' && response.status >= 500) {
        return await caches.match(RECOVERY_PAGE) || response;
      }
      if (isSafeCacheResponse(response)) {
        const cache = await caches.open(CACHE_NAME);
        await cache.put(event.request, response.clone());
      }
      return response;
    } catch {
      if (event.request.mode === 'navigate') {
        return await caches.match(RECOVERY_PAGE) || new Response('网站暂时无法连接，请稍后重试。', {
          status: 503,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }
      const cached = await caches.match(event.request);
      if (cached) return cached;
      throw new Error('离线且没有可用缓存');
    }
  })());
});
