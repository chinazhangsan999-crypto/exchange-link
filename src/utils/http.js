'use strict';

const { IS_PRODUCTION } = require('../config/env');

const ok = (res, data = null, msg = '操作成功') => res.json({ code: 200, msg, data });
const fail = (res, msg, code = 400) => res.status(code).json({ code, msg, data: null });

function safeApiErrorMessage(error, fallback = '服务器内部错误，请稍后重试') {
  const rawMessage = String(error?.message || '').trim();
  return IS_PRODUCTION ? fallback : (rawMessage || fallback);
}

function isUniqueConstraintError(error) {
  return (error?.code === 'SQLITE_CONSTRAINT' && /UNIQUE/i.test(String(error?.message || '')))
    || /UNIQUE constraint failed/i.test(String(error?.message || ''));
}

module.exports = { ok, fail, safeApiErrorMessage, isUniqueConstraintError };
