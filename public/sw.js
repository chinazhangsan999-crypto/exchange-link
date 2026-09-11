/** 星环导航轻量离线缓存：验证和敏感操作永不缓存，普通页面网络优先。 */
const CACHE_NAME = 'nav-cache-v4-remove-node-switcher';
const STATIC_ASSETS = [
  '/', '/index.html', '/script.js?v=20260910-remove-node-switcher', '/style.css', '/manifest.json',
  '/tooltip.css', '/apply.css', '/apply-category.css', '/no-icons.css',
  '/header-cleanup.css', '/mobile-nav.css', '/enhance.css', '/pwa.css',
  '/icons/icon-192.png', '/icons/icon-512.png'
];
const NEVER_CACHE_PATHS = new Set([
  '/verify.html', '/verify.css', '/verify.js', '/go', '/api/links/apply'
]);

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))));
  self.clients.claim();
});

function mustUseNetwork(url) {
  return NEVER_CACHE_PATHS.has(url.pathname) || url.pathname.startsWith('/api/verify/');
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
      if (isSafeCacheResponse(response)) {
        const cache = await caches.open(CACHE_NAME);
        await cache.put(event.request, response.clone());
      }
      return response;
    } catch {
      const cached = await caches.match(event.request);
      if (cached) return cached;
      if (event.request.mode === 'navigate') return caches.match('/index.html');
      throw new Error('离线且没有可用缓存');
    }
  })());
});
