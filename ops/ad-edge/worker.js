const encoder = new TextEncoder();
const VERSION = '2.0.1';

function base64urlBytes(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}
function base64urlText(value) { return new TextDecoder().decode(base64urlBytes(value)); }
function bytesToBase64(bytes) {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(binary);
}
function bytesToBase64url(bytes) { return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

async function hmacBytes(secret, value) {
  const key = await crypto.subtle.importKey('raw', typeof secret === 'string' ? encoder.encode(secret) : secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
}
function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

async function verifyTicket(token, env) {
  const [encoded, signature, extra] = String(token || '').split('.');
  if (!encoded || !signature || extra) throw new Error('invalid_ticket');
  let payload;
  try { payload = JSON.parse(base64urlText(encoded)); } catch { throw new Error('invalid_ticket'); }
  const now = Math.floor(Date.now() / 1000);
  if (!/^\d+$/.test(String(payload.site_id || ''))
    || !/^\d+$/.test(String(payload.ad_id || ''))
    || !['direct', 'sandbox'].includes(payload.render_mode)
    || !['central', 'local'].includes(payload.ad_source || 'central')
    || String(payload.profile_id || '') !== String(env.PROFILE_ID || '')
    || typeof payload.frontend_origin !== 'string'
    || !/^https:\/\/[^/]+$/i.test(payload.frontend_origin)
    || !Number.isInteger(payload.issued_at)
    || !Number.isInteger(payload.expires_at)
    || payload.issued_at > now + 30
    || payload.expires_at < now
    || payload.expires_at - payload.issued_at > 300
    || !/^[A-Za-z0-9_-]{16,64}$/.test(String(payload.nonce || ''))) throw new Error('invalid_ticket');
  const siteKey = await hmacBytes(env.BACKEND_SECRET, `site:${payload.site_id}`);
  const expected = await hmacBytes(siteKey, encoded);
  if (!equalBytes(expected, base64urlBytes(signature))) throw new Error('invalid_ticket');
  return payload;
}

async function fetchAd(payload, env) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const source = payload.ad_source === 'local' ? 'local' : 'central';
  const canonical = `${timestamp}\n${payload.profile_id}\n${payload.site_id}\n${payload.ad_id}\n${payload.render_mode}\n${source}`;
  const signature = await hmacBytes(env.BACKEND_SECRET, canonical);
  const url = `${String(env.BACKEND_ORIGIN || '').replace(/\/$/, '')}/api/internal/ad-edge/render/${payload.site_id}/${payload.ad_id}`;
  const response = await fetch(url, { headers: {
    accept: 'application/json',
    'x-ad-edge-profile': payload.profile_id,
    'x-ad-edge-mode': payload.render_mode,
    'x-ad-edge-source': source,
    'x-ad-edge-timestamp': timestamp,
    'x-ad-edge-signature': bytesToBase64url(signature)
  }});
  const body = await response.json().catch(() => null);
  if (!response.ok || typeof body?.data?.code !== 'string') throw new Error(body?.message || 'ad_unavailable');
  return body.data;
}

function commonHeaders(contentType) {
  return {
    'content-type': contentType,
    'cache-control': 'private, no-store, max-age=0',
    pragma: 'no-cache',
    'x-content-type-options': 'nosniff',
    'x-robots-tag': 'noindex, nofollow',
    'referrer-policy': 'no-referrer'
  };
}
function directResponse(data, payload) {
  return new Response(JSON.stringify({ code: data.code, integrity: data.integrity }), { headers: {
    ...commonHeaders('application/json; charset=utf-8'),
    'access-control-allow-origin': payload.frontend_origin,
    'access-control-allow-credentials': 'false',
    vary: 'Origin'
  }});
}
function frameResponse(data, payload) {
  const encodedCode = bytesToBase64(encoder.encode(data.code));
  const bootstrap = `(()=>{const raw=new TextDecoder().decode(Uint8Array.from(atob(${JSON.stringify(encodedCode)}),c=>c.charCodeAt(0)));if(/^(?:\\uFEFF)?\\s*(?:<!--[\\s\\S]*?-->\\s*)*<\\/?[a-z][\\w:-]*(?:\\s[^<>]*)?>/i.test(raw)){document.write(raw)}else{const s=document.createElement('script');s.src=URL.createObjectURL(new Blob([raw],{type:'text/javascript'}));s.onload=()=>URL.revokeObjectURL(s.src);document.head.append(s)}})();`;
  const bridge = `(()=>{const send=(type,extra={})=>parent.postMessage({type,nonce:${JSON.stringify(payload.nonce)},ad_id:${Number(payload.client_ad_id || 0)},...extra},${JSON.stringify(payload.frontend_origin)});addEventListener('error',()=>send('ad-error'));new ResizeObserver(()=>send('ad-resize',{height:Math.min(800,Math.max(50,document.documentElement.scrollHeight||document.body.scrollHeight||120))})).observe(document.documentElement);send('ad-ready')})();`;
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><base target="_blank"><style>html,body{margin:0;padding:0;background:transparent;overflow:hidden}</style></head><body><script>${bootstrap}<\/script><script>${bridge}<\/script></body></html>`;
  const csp = `default-src 'none'; script-src 'unsafe-inline' blob: https:; style-src 'unsafe-inline' https:; img-src data: blob: https: http:; connect-src https:; frame-src https:; object-src 'none'; base-uri 'none'; form-action https:; frame-ancestors ${payload.frontend_origin}`;
  return new Response(html, { headers: { ...commonHeaders('text/html; charset=utf-8'), 'content-security-policy': csp, 'permissions-policy': 'camera=(), microphone=(), geolocation=(), clipboard-read=(), clipboard-write=()' } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/health') return Response.json({ status: 'ok', version: VERSION }, { headers: commonHeaders('application/json; charset=utf-8') });
    const match = /^\/(direct|frame)\/([A-Za-z0-9_.-]+)$/.exec(url.pathname);
    if (request.method !== 'GET' || !match) return new Response('Not Found', { status: 404, headers: commonHeaders('text/plain; charset=utf-8') });
    try {
      const payload = await verifyTicket(match[2], env);
      const requestedMode = match[1] === 'frame' ? 'sandbox' : 'direct';
      if (payload.render_mode !== requestedMode) throw new Error('mode_mismatch');
      if (requestedMode === 'direct' && request.headers.get('origin') !== payload.frontend_origin) throw new Error('origin_mismatch');
      const data = await fetchAd(payload, env);
      return requestedMode === 'direct' ? directResponse(data, payload) : frameResponse(data, payload);
    } catch {
      return Response.json({ code: 403, message: '请求无法处理' }, { status: 403, headers: commonHeaders('application/json; charset=utf-8') });
    }
  }
};
