const PROXIED_PATHS = [
  '/api/',
  '/go',
  '/favicon.ico',
  '/.well-known/route-health.gif',
  '/uploads/logo/'
];

const SCRIPT_CLIENT_PATTERN = /(?:python-requests|curl\/|wget\/|scrapy|go-http-client|aiohttp|httpx\/)/i;
const KNOWN_CRAWLER_PATTERN = /(?:googlebot|bingbot|baiduspider|yandexbot|sogou|bytespider|gptbot|chatgpt-user|oai-searchbot|claudebot|claude-web|anthropic-ai|ccbot|cohere-ai|perplexitybot|amazonbot|applebot-extended|meta-externalagent|diffbot|headlesschrome)/i;

function isProtectedReadPath(pathname) {
  return pathname === '/api/read/bootstrap'
    || pathname === '/api/links'
    || /^\/api\/links\/\d+$/.test(pathname)
    || pathname === '/api/showcase';
}

function denyObviousScriptClient(request, pathname) {
  if (!isProtectedReadPath(pathname)) return null;
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent && !SCRIPT_CLIENT_PATTERN.test(userAgent)) return null;
  return new Response(JSON.stringify({ code: 403, msg: '请求无法处理', data: null }), {
    status: 403,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'private, no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Robots-Tag': 'noindex, nofollow'
    }
  });
}

function denyKnownCrawler(request, env) {
  if (String(env.BOT_GATE_MODE || 'off').toLowerCase() !== 'enforce') return null;
  const userAgent = request.headers.get('User-Agent') || '';
  if (!KNOWN_CRAWLER_PATTERN.test(userAgent)) return null;
  return new Response('Not Found', {
    status: 404,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'private, no-store',
      'X-Robots-Tag': 'noindex, nofollow'
    }
  });
}

function toHex(bytes) {
  return [...new Uint8Array(bytes)].map(value => value.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(bytes) {
  return toHex(await crypto.subtle.digest('SHA-256', bytes));
}

async function sign(secret, value) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return toHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value)));
}

function nonce() {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function shouldProxy(pathname) {
  return PROXIED_PATHS.some(prefix => pathname === prefix || pathname.startsWith(prefix));
}

function isAdminPath(pathname) {
  return pathname === '/admin'
    || pathname.startsWith('/admin/')
    || pathname === '/api/admin'
    || pathname.startsWith('/api/admin/');
}

function cookieExists(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  return cookie.split(';').some(item => item.trim().startsWith(`${name}=`));
}

function sourceSid(url) {
  const routeMatch = url.pathname.match(/^\/r\/([^/]+)\/?$/);
  if (routeMatch) {
    try { return { present: true, value: decodeURIComponent(routeMatch[1]) }; }
    catch { return { present: true, value: '' }; }
  }
  if ((url.pathname === '/' || url.pathname === '/index.html') && url.searchParams.has('sid')) {
    return { present: true, value: url.searchParams.get('sid') || '' };
  }
  return { present: false, value: '' };
}

function cleanLandingUrl(url) {
  if (url.pathname.startsWith('/r/')) return '/';
  const clean = new URL(url);
  clean.searchParams.delete('sid');
  return `${clean.pathname}${clean.search}`;
}

function copySetCookies(fromHeaders, toHeaders) {
  if (typeof fromHeaders.getSetCookie === 'function') {
    for (const value of fromHeaders.getSetCookie()) toHeaders.append('Set-Cookie', value);
    return;
  }
  const value = fromHeaders.get('Set-Cookie');
  if (value) toHeaders.append('Set-Cookie', value);
}

function withPublicSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('Content-Security-Policy', "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline' blob: https:; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: http:; connect-src 'self' https: http:; frame-src https: http:; font-src 'self' data:");
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-Robots-Tag', 'noindex, nofollow');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function verifiedClientIp(request) {
  return request.headers.get('CF-Connecting-IP') || '127.0.0.1';
}

async function signedHeaders(request, env, path, rawBody) {
  if (!env.FRONTEND_PROXY_SECRET || env.FRONTEND_PROXY_SECRET.length < 32) {
    throw new Error('FRONTEND_PROXY_SECRET 未配置或长度不足 32 位');
  }
  const requestUrl = new URL(request.url);
  const timestamp = Date.now().toString();
  const requestNonce = nonce();
  const origin = requestUrl.origin.toLowerCase();
  const clientIp = verifiedClientIp(request);
  const botManagement = request.cf?.botManagement;
  // 这两个结论都由 Cloudflare 在边缘持续维护。signedAgent 是 Web Bot Auth
  // 的官方确认结果；只在任一官方强信号为真时向源站传递“已确认”。
  const confirmedBot = botManagement?.verifiedBot === true || botManagement?.signedAgent === true ? '1' : '0';
  const canonical = [
    timestamp,
    requestNonce,
    request.method.toUpperCase(),
    path,
    origin,
    clientIp,
    confirmedBot,
    await sha256Hex(rawBody)
  ].join('\n');

  const headers = new Headers(request.headers);
  for (const name of [
    'host',
    'cf-connecting-ip',
    'x-forwarded-for',
    'x-real-ip',
    'x-frontend-origin',
    'x-verified-client-ip',
    'x-edge-confirmed-bot',
    'x-proxy-timestamp',
    'x-proxy-nonce',
    'x-proxy-signature'
  ]) headers.delete(name);
  headers.set('X-Frontend-Origin', origin);
  headers.set('X-Verified-Client-IP', clientIp);
  headers.set('X-Edge-Confirmed-Bot', confirmedBot);
  headers.set('X-Proxy-Timestamp', timestamp);
  headers.set('X-Proxy-Nonce', requestNonce);
  headers.set('X-Proxy-Signature', await sign(env.FRONTEND_PROXY_SECRET, canonical));
  return headers;
}

async function proxyRequest(request, env) {
  const incoming = new URL(request.url);
  const upstream = new URL(`${incoming.pathname}${incoming.search}`, env.API_ORIGIN);
  const rawBody = ['GET', 'HEAD'].includes(request.method)
    ? new Uint8Array()
    : new Uint8Array(await request.clone().arrayBuffer());
  const headers = await signedHeaders(request, env, `${incoming.pathname}${incoming.search}`, rawBody);
  const response = await fetch(upstream, {
    method: request.method,
    headers,
    body: rawBody.byteLength ? rawBody : undefined,
    redirect: 'manual'
  });
  return new Response(response.body, response);
}

async function prepareLanding(request, env) {
  const incoming = new URL(request.url);
  const sid = sourceSid(incoming);
  const payload = {
    requestPath: `${incoming.pathname}${incoming.search}`,
    referer: request.headers.get('Referer') || '',
    userAgent: request.headers.get('User-Agent') || ''
  };
  if (sid.present) payload.sourceSid = sid.value;

  const rawBody = new TextEncoder().encode(JSON.stringify(payload));
  const path = '/internal/frontend/landing';
  const headers = await signedHeaders(
    new Request(request.url, { method: 'POST', headers: request.headers }),
    env,
    path,
    rawBody
  );
  headers.set('Content-Type', 'application/json');
  return fetch(new URL(path, env.API_ORIGIN), {
    method: 'POST',
    headers,
    body: rawBody,
    redirect: 'manual'
  });
}

async function publicRuntimeConfig(request, env) {
  const path = '/api/config/public';
  const headers = await signedHeaders(new Request(request.url, { method: 'GET', headers: request.headers }), env, path, new Uint8Array());
  const response = await fetch(new URL(path, env.API_ORIGIN), { headers, redirect: 'manual' });
  if (!response.ok) return {};
  const payload = await response.json().catch(() => null);
  return payload?.data && typeof payload.data === 'object' ? payload.data : {};
}

async function servePublicHtml(request, env, landingResponse = null) {
  const asset = await env.ASSETS.fetch(request);
  if (!asset.ok || !(asset.headers.get('content-type') || '').includes('text/html')) {
    return withPublicSecurityHeaders(asset);
  }
  const config = await publicRuntimeConfig(request, env).catch(() => ({}));
  const publicConfig = {
    ad_api_enabled: config.ad_api_enabled === true,
    ad_api_origin: /^https:\/\/[^/]+$/i.test(String(config.ad_api_origin || '')) ? config.ad_api_origin : '',
    ad_api_worker_version: String(config.ad_api_worker_version || '')
  };
  const marker = `<script id="webring-runtime-config" type="application/json">${JSON.stringify(publicConfig).replace(/</g, '\\u003c')}</script>`;
  const html = (await asset.text()).replace('</head>', `${marker}</head>`);
  const headers = new Headers(asset.headers);
  headers.delete('content-length');
  headers.set('content-type', 'text/html; charset=utf-8');
  if (landingResponse) copySetCookies(landingResponse.headers, headers);
  if (headers.has('Set-Cookie')) headers.set('Cache-Control', 'private, no-store');
  return withPublicSecurityHeaders(new Response(html, { status: asset.status, statusText: asset.statusText, headers }));
}

async function serveLanding(request, env) {
  const url = new URL(request.url);
  const sid = sourceSid(url);
  let landingResponse = null;
  // 已持有尚未消费的 Claim 时不重复签发，也不产生重复的“未入站”流水。
  if (!cookieExists(request, 'track_session')) landingResponse = await prepareLanding(request, env);

  if (sid.present) {
    const headers = new Headers({
      Location: cleanLandingUrl(url),
      'Cache-Control': 'private, no-store',
      'Referrer-Policy': 'no-referrer'
    });
    if (landingResponse) copySetCookies(landingResponse.headers, headers);
    return new Response(null, { status: 302, headers });
  }

  return servePublicHtml(request, env, landingResponse);
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (isAdminPath(url.pathname)) {
        return withPublicSecurityHeaders(new Response('Not Found', {
          status: 404,
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
        }));
      }
      const crawlerResponse = denyKnownCrawler(request, env);
      if (crawlerResponse) return crawlerResponse;
      const scriptClientResponse = denyObviousScriptClient(request, url.pathname);
      if (scriptClientResponse) return scriptClientResponse;
      if (shouldProxy(url.pathname)) return await proxyRequest(request, env);
      if (request.method === 'GET'
        && (url.pathname === '/' || url.pathname === '/index.html' || url.pathname.startsWith('/r/'))) {
        return await serveLanding(request, env);
      }
      if (request.method === 'GET' && ['/site-detail', '/site-detail.html'].includes(url.pathname)) {
        return await servePublicHtml(request, env);
      }
      return withPublicSecurityHeaders(await env.ASSETS.fetch(request));
    } catch (error) {
      console.error('公共前端边缘代理失败', error);
      return new Response('服务暂时不可用', {
        status: 502,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
      });
    }
  }
};
