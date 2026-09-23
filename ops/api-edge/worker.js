const PROXY_HEADERS = [
  'x-frontend-origin',
  'x-verified-client-ip',
  'x-proxy-timestamp',
  'x-proxy-nonce',
  'x-proxy-signature'
];

const EDGE_BOT_HEADER = 'x-edge-confirmed-bot';

const ALLOWED_PATH_PREFIXES = [
  '/api/',
  '/uploads/logo/'
];

const ALLOWED_EXACT_PATHS = new Set([
  '/go',
  '/favicon.ico',
  '/.well-known/route-health.gif',
  '/internal/frontend/landing'
]);

function toHex(bytes) {
  return [...new Uint8Array(bytes)].map(value => value.toString(16).padStart(2, '0')).join('');
}

function fromHex(value) {
  if (!/^[a-f0-9]{64}$/i.test(value || '')) return null;
  return new Uint8Array(value.match(/.{2}/g).map(part => Number.parseInt(part, 16)));
}

async function sha256Hex(bytes) {
  return toHex(await crypto.subtle.digest('SHA-256', bytes));
}

function notFound() {
  return new Response('Not Found', {
    status: 404,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Robots-Tag': 'noindex, nofollow'
    }
  });
}

function allowedOrigins(env) {
  return new Set(String(env.ALLOWED_FRONTEND_ORIGINS || '')
    .split(',')
    .map(value => value.trim().toLowerCase().replace(/\/$/, ''))
    .filter(Boolean));
}

function isAllowedPath(pathname) {
  return ALLOWED_EXACT_PATHS.has(pathname)
    || ALLOWED_PATH_PREFIXES.some(prefix => pathname.startsWith(prefix));
}

async function verifyFrontendSignature(request, env, rawBody) {
  const values = Object.fromEntries(PROXY_HEADERS.map(name => [name, request.headers.get(name) || '']));
  if (PROXY_HEADERS.some(name => !values[name])) return false;
  if (!env.FRONTEND_PROXY_SECRET || env.FRONTEND_PROXY_SECRET.length < 32) return false;

  // 新版公共前台把 Cloudflare 已确认机器人结论纳入签名；未带该字段的
  // 旧前台继续按旧格式验签，便于多个前台 Worker 分批滚动升级。
  const confirmedBotHeader = request.headers.get(EDGE_BOT_HEADER);
  if (confirmedBotHeader !== null && !['0', '1'].includes(confirmedBotHeader)) return false;

  const timestamp = Number(values['x-proxy-timestamp']);
  const maxSkewMs = Math.max(5_000, Math.min(300_000, Number(env.MAX_SKEW_MS) || 30_000));
  if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > maxSkewMs) return false;
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(values['x-proxy-nonce'])) return false;

  const origin = values['x-frontend-origin'].toLowerCase().replace(/\/$/, '');
  if (!allowedOrigins(env).has(origin)) return false;

  const url = new URL(request.url);
  const canonicalParts = [
    String(timestamp),
    values['x-proxy-nonce'],
    request.method.toUpperCase(),
    `${url.pathname}${url.search}`,
    origin,
    values['x-verified-client-ip']
  ];
  if (confirmedBotHeader !== null) canonicalParts.push(confirmedBotHeader);
  canonicalParts.push(await sha256Hex(rawBody));
  const canonical = canonicalParts.join('\n');

  const signature = fromHex(values['x-proxy-signature']);
  if (!signature) return false;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(env.FRONTEND_PROXY_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  return crypto.subtle.verify('HMAC', key, signature, new TextEncoder().encode(canonical));
}

async function proxyToOrigin(request, env, rawBody) {
  const incoming = new URL(request.url);
  const upstream = new URL(`${incoming.pathname}${incoming.search}`, env.API_ORIGIN);
  const headers = new Headers(request.headers);
  headers.delete('host');
  const response = await fetch(upstream, {
    method: request.method,
    headers,
    body: rawBody.byteLength ? rawBody : undefined,
    redirect: 'manual'
  });
  const responseHeaders = new Headers(response.headers);
  responseHeaders.set('Cache-Control', 'private, no-store');
  responseHeaders.set('X-Content-Type-Options', 'nosniff');
  responseHeaders.set('X-Robots-Tag', 'noindex, nofollow');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders
  });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (!isAllowedPath(url.pathname)) return notFound();

      const rawBody = ['GET', 'HEAD'].includes(request.method)
        ? new Uint8Array()
        : new Uint8Array(await request.clone().arrayBuffer());

      if (url.pathname !== '/api/health'
        && !(await verifyFrontendSignature(request, env, rawBody))) {
        return notFound();
      }

      return await proxyToOrigin(request, env, rawBody);
    } catch (error) {
      console.error('数据边缘代理失败', error);
      return new Response('服务暂时不可用', {
        status: 502,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
      });
    }
  }
};
