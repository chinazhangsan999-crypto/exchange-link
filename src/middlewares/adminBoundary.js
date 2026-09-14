'use strict';

const { ADMIN_FRONTEND_ORIGIN } = require('../config/env');

function isAdminSurface(req) {
  const path = String(req.path || '');
  return path === '/admin'
    || path.startsWith('/admin/')
    || path === '/api/admin'
    || path.startsWith('/api/admin/');
}

// 总后台 SSO 的第一跳尚在旧主站完成票据兑换；它不读取后台数据，且兑换成功后
// 立即跳转到独立后台域。只保留这两个精确路径的兼容桥，不能放宽整个 /api/admin。
function isControlCenterSsoBridge(req) {
  const path = String(req.path || '');
  return path === '/api/admin/control-center/login'
    || path === '/api/admin/control-center/sso';
}

/**
 * 物理分离后，主站/API Origin 不再直接暴露后台。只有后台边缘 Worker
 * 通过 HMAC 验证并写入 trustedFrontendOrigin 后，才允许访问后台页面或 API。
 */
function requireAdminFrontendBoundary(req, res, next) {
  if (!ADMIN_FRONTEND_ORIGIN || !isAdminSurface(req)) return next();
  if (isControlCenterSsoBridge(req)) return next();
  if (req.trustedFrontendOrigin === ADMIN_FRONTEND_ORIGIN) return next();
  return res.status(404).end();
}

module.exports = { requireAdminFrontendBoundary };
