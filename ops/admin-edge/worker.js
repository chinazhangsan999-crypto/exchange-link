function allowedPath(pathname) {
  return pathname === '/admin'
    || pathname.startsWith('/admin/')
    || pathname === '/api/admin'
    || pathname.startsWith('/api/admin/')
    || pathname.startsWith('/uploads/logo/');
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(bytes) {
  return bytesToHex(await crypto.subtle.digest('SHA-256', bytes));
}

function randomNonce() {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sign(secret, value) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return bytesToHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value)));
}

function copySetCookies(fromHeaders, toHeaders) {
  if (typeof fromHeaders.getSetCookie === 'function') {
    for (const cookie of fromHeaders.getSetCookie()) toHeaders.append('Set-Cookie', cookie);
    return;
  }
  // Cloudflare Workers 的部分兼容运行时仍提供 getAll，而非标准 getSetCookie。
  // 多个 Set-Cookie 绝不能通过 get() 合并为逗号字符串，否则浏览器会丢弃
  // 或只保存其中一个 Cookie，导致 SSO 后所有受保护 API 都显示为空。
  if (typeof fromHeaders.getAll === 'function') {
    for (const cookie of fromHeaders.getAll('Set-Cookie')) toHeaders.append('Set-Cookie', cookie);
    return;
  }
  const cookie = fromHeaders.get('Set-Cookie');
  if (cookie) toHeaders.append('Set-Cookie', cookie);
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

async function signedHeaders(request, env, path, rawBody) {
  if (!env.FRONTEND_PROXY_SECRET || env.FRONTEND_PROXY_SECRET.length < 32) {
    throw new Error('后台边缘代理未配置 FRONTEND_PROXY_SECRET');
  }
  const url = new URL(request.url);
  const timestamp = String(Date.now());
  const nonce = randomNonce();
  const origin = url.origin.toLowerCase();
  const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
  const canonical = [
    timestamp, nonce, request.method.toUpperCase(), path, origin, clientIp, await sha256Hex(rawBody)
  ].join('\n');
  const headers = new Headers(request.headers);
  for (const name of [
    'host', 'cf-connecting-ip', 'x-forwarded-for', 'x-real-ip', 'x-frontend-origin',
    'x-verified-client-ip', 'x-proxy-timestamp', 'x-proxy-nonce', 'x-proxy-signature'
  ]) headers.delete(name);
  headers.set('X-Frontend-Origin', origin);
  headers.set('X-Verified-Client-IP', clientIp);
  headers.set('X-Proxy-Timestamp', timestamp);
  headers.set('X-Proxy-Nonce', nonce);
  headers.set('X-Proxy-Signature', await sign(env.FRONTEND_PROXY_SECRET, canonical));
  return headers;
}

async function proxy(request, env) {
  const incoming = new URL(request.url);
  const path = `${incoming.pathname}${incoming.search}`;
  const rawBody = ['GET', 'HEAD'].includes(request.method)
    ? new Uint8Array()
    : new Uint8Array(await request.clone().arrayBuffer());
  const response = await fetch(new URL(path, env.API_ORIGIN), {
    method: request.method,
    headers: await signedHeaders(request, env, path, rawBody),
    body: rawBody.byteLength ? rawBody : undefined,
    redirect: 'manual'
  });
  const headers = new Headers(response.headers);
  // Response 的 Headers 已可能包含 Set-Cookie。先删除再按原响应逐条复制，
  // 避免 Worker 把同一个管理员 Cookie 追加两次，导致浏览器会话落地不稳定。
  headers.delete('Set-Cookie');
  copySetCookies(response.headers, headers);
  headers.set('Cache-Control', 'no-store, private');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Robots-Tag', 'noindex, nofollow');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!allowedPath(url.pathname)) return notFound();
    try {
      return await proxy(request, env);
    } catch (error) {
      console.error('后台边缘代理失败', error);
      return new Response('服务暂时不可用', {
        status: 502,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
      });
    }
  }
};
