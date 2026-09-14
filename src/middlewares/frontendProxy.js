'use strict';

const FrontendProxyService = require('../services/FrontendProxyService');
const { PUBLIC_FRONTEND_MODE } = require('../config/env');

const PROXY_HEADERS = [
  'x-frontend-origin',
  'x-verified-client-ip',
  'x-proxy-timestamp',
  'x-proxy-nonce',
  'x-proxy-signature'
];

async function acceptTrustedFrontendProxy(req, res, next) {
  const present = PROXY_HEADERS.filter(name => req.get(name));
  if (!present.length) return next();
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
  '/api/captcha',
  '/api/links',
  '/api/showcase',
  '/go'
];

/**
 * 分离模式下，公开业务接口只接受白名单边缘前端转发。
 * 健康检查、后台与防失联发布页依赖的 /api/mirrors 保持可直连。
 */
function requireSeparatedFrontendProxy(req, res, next) {
  if (PUBLIC_FRONTEND_MODE !== 'separated') return next();
  const path = String(req.path || '');
  if (!PUBLIC_PROXY_PATHS.some(prefix => path === prefix || path.startsWith(prefix))) return next();
  if (req.trustedFrontendOrigin && req.verifiedClientIp) return next();
  return res.status(404).end();
}

module.exports = {
  acceptTrustedFrontendProxy,
  requireTrustedFrontendProxy,
  requireSeparatedFrontendProxy
};
