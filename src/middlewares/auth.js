'use strict';

const jwt = require('jsonwebtoken');
const { ADMIN_JWT_SECRET } = require('../config/env');

/** JWT 管理身份校验：所有受保护后台接口必须携带 Bearer Token。 */
function requireAdmin(req, res, next) {
  const token = req.get('authorization')?.replace(/^Bearer\s+/i, '');
  if (!token) {
    return res.status(401).json({ code: 401, msg: '需要管理员令牌', data: null });
  }

  let payload;
  try {
    payload = jwt.verify(token, ADMIN_JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return res.status(401).json({ code: 401, msg: '登录已过期或令牌无效', data: null });
  }

  if (payload?.role !== 'admin' || payload?.type !== 'admin') {
    return res.status(403).json({ code: 403, msg: '令牌没有管理员权限', data: null });
  }

  req.admin = payload;
  return next();
}

module.exports = { requireAdmin };
