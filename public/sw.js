/** 星环导航轻量离线缓存：网络优先，网络不可用时回退到安装期缓存。 */
const CACHE_NAME = 'nav-cache-v1';
const STATIC_ASSETS = [
  '/', '/index.html', '/script.js', '/style.css', '/manifest.json',
  '/tooltip.css', '/apply.css', '/apply-category.css', '/no-icons.css',
  '/header-cleanup.css', '/mobile-nav.css', '/enhance.css', '/pwa.css',
  '/icons/icon-192.png', '/icons/icon-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))));
  self.clients.claim();
});

// 网络优先策略确保站点列表保持实时；离线时使用已缓存的页面与静态资源。
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request).then(cached => cached || caches.match('/'))));
});
