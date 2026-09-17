'use strict';

const FrontendProxyService = require('../services/FrontendProxyService');
const { FRONTEND_PROXY_API_HOSTS } = require('../config/env');

const PROXY_HEADERS = [
  'x-frontend-origin',
  'x-verified-client-ip',
  'x-proxy-timestamp',
  'x-proxy-nonce',
  'x-proxy-signature'
];

const DIRECT_API_HOST_PATHS = new Set([
  '/api/health',
  '/setup',
  '/setup/client.js',
  '/api/setup/status',
  '/api/setup/deploy'
]);

function requestHostname(req) {
  const host = String(req.headers.host || '').trim().toLowerCase();
  if (host.startsWith('[')) return host.slice(1, host.indexOf(']'));
  return host.split(':', 1)[0].replace(/\.$/, '');
}

function isProtectedApiHost(req) {
  return FRONTEND_PROXY_API_HOSTS.includes(requestHostname(req));
}

async function acceptTrustedFrontendProxy(req, res, next) {
  const present = PROXY_HEADERS.filter(name => req.get(name));
  if (!present.length) {
    if (isProtectedApiHost(req) && !DIRECT_API_HOST_PATHS.has(req.path)) {
      return res.status(404).end();
    }
    return next();
  }
  if (present.length !== PROXY_HEADERS.length) {
    return res.status(401).json({ code: 401, msg: '前台代理上下文不完整', data: null });
  }

  try {
    const result = await FrontendProxyService.verifyProxyRequest(req);
    if (!result.ok) {
      return res.status(401).json({ code: 401, msg: '前台代理身份校验失败', data: null });
    }
    req.verifiedClientIp = result.clientIp;
    req.trustedFrontendOrigin = result.origin;
    return next();
  } catch (error) {
    console.error('[Frontend Proxy] 验签失败：', error.message);
    return res.status(503).json({ code: 503, msg: '前台代理校验暂不可用', data: null });
  }
}

function requireTrustedFrontendProxy(req, res, next) {
  if (req.trustedFrontendOrigin && req.verifiedClientIp) return next();
  return res.status(404).end();
}

const PUBLIC_PROXY_PATHS = [
  '/api/read/',
  '/api/sys-trap/',
  '/api/verify/',
  '/api/analytics/',
  '/api/inflow/',
  '/api/track/',
  '/api/config',
  '/api/categories',
  '/api/mirrors',
  '/api/captcha',
  '/api/links',
  '/api/showcase',
  '/go'
];

/**
 * 公开业务接口永久只接受白名单边缘前端转发。
 * /api/health 是唯一允许直接读取的公共服务状态接口。
 */
function requireFrontendProxy(req, res, next) {
  const path = String(req.path || '');
  if (!PUBLIC_PROXY_PATHS.some(prefix => path === prefix || path.startsWith(prefix))) return next();
  if (req.trustedFrontendOrigin && req.verifiedClientIp) return next();
  return res.status(404).end();
}

module.exports = {
  acceptTrustedFrontendProxy,
  requireTrustedFrontendProxy,
  requireFrontendProxy
};
