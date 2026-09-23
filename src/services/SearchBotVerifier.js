'use strict';

const dns = require('node:dns').promises;
const net = require('node:net');
const { LRUCache } = require('lru-cache');
const cache = new LRUCache({ max: 20000, ttl: 6 * 60 * 60 * 1000 });
const PROVIDERS = Object.freeze([
  { name: 'Googlebot', ua: /googlebot/i, suffixes: ['.googlebot.com', '.google.com', '.googleusercontent.com'] },
  { name: 'Bingbot', ua: /(?:bingbot|adidxbot)/i, suffixes: ['.search.msn.com'] },
  { name: 'Baiduspider', ua: /baiduspider/i, suffixes: ['.baidu.com', '.baidu.jp'] },
  { name: 'YandexBot', ua: /yandex(?:bot|images|accessibilitybot)/i, suffixes: ['.yandex.ru', '.yandex.net', '.yandex.com'] }
]);
function normalizeIp(value) { const ip = String(value || '').trim().replace(/^::ffff:/i, ''); return net.isIP(ip) ? ip : ''; }
function providerFor(userAgent) { return PROVIDERS.find(item => item.ua.test(String(userAgent || ''))) || null; }
async function verify(userAgent, rawIp) {
  const provider = providerFor(userAgent); const ip = normalizeIp(rawIp);
  if (!provider || !ip) return { candidate: Boolean(provider), verified: false, provider: provider?.name || '', reason: ip ? 'unsupported_ua' : 'invalid_ip' };
  const key = `${provider.name}:${ip}`; const cached = cache.get(key); if (cached) return cached;
  let result;
  try {
    const names = await dns.reverse(ip);
    const hostname = names.map(name => String(name).toLowerCase().replace(/\.$/, '')).find(name => provider.suffixes.some(suffix => name.endsWith(suffix)));
    if (!hostname) result = { candidate: true, verified: false, provider: provider.name, reason: 'reverse_suffix_mismatch' };
    else { const forward = await dns.lookup(hostname, { all: true, verbatim: true }); const verified = forward.some(item => normalizeIp(item.address) === ip); result = { candidate: true, verified, provider: provider.name, hostname, reason: verified ? 'forward_confirmed' : 'forward_ip_mismatch' }; }
  } catch (error) { result = { candidate: true, verified: false, provider: provider.name, reason: String(error.code || 'dns_failed') }; }
  cache.set(key, result); return result;
}
module.exports = { verify, providerFor };
