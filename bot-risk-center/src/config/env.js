'use strict';

function boundedInteger(value, fallback, min, max) {
  const parsed = Number.parseInt(value || '', 10);
  return Number.isInteger(parsed) ? Math.max(min, Math.min(max, parsed)) : fallback;
}

function parseClients(raw) {
  if (!raw) return {};
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch { throw new Error('BOT_RISK_CLIENTS_JSON 必须是有效 JSON 对象'); }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('BOT_RISK_CLIENTS_JSON 必须是 client_id 到 secret 的对象');
  }
  for (const [clientId, secret] of Object.entries(parsed)) {
    if (!/^[A-Za-z0-9_-]{3,64}$/.test(clientId) || String(secret).length < 32) {
      throw new Error('风险中心 client_id 格式无效或 secret 少于 32 字符');
    }
  }
  return Object.freeze({ ...parsed });
}

const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const PORT = boundedInteger(process.env.PORT, 4100, 1, 65535);
const LISTEN_HOST = String(process.env.RISK_LISTEN_HOST || '127.0.0.1').trim();
const DATABASE_URL = String(process.env.DATABASE_URL || '').trim();
const REDIS_URL = String(process.env.REDIS_URL || '').trim();
const ADMIN_USERNAME = String(process.env.BOT_RISK_ADMIN_USERNAME || 'admin').trim();
const ADMIN_PASSWORD_HASH = String(process.env.BOT_RISK_ADMIN_PASSWORD_HASH
  || 'scrypt$10ae0405c79e760036f98387d0fccf38$59e983d31ff235bf5c073671bdffa6900d60e170f152467f885b0c9e689d92b19704f9be233f2d719c2a382f311b82cef85036b484cac277c7173743066c5fe7').trim();
const CLIENTS = parseClients(process.env.BOT_RISK_CLIENTS_JSON || '');
const EVENT_RETENTION_DAYS = boundedInteger(process.env.EVENT_RETENTION_DAYS, 7, 1, 90);
const CROWDSEC_LAPI_URL = String(process.env.CROWDSEC_LAPI_URL || '').trim().replace(/\/$/, '');
const CROWDSEC_LAPI_KEY = String(process.env.CROWDSEC_LAPI_KEY || '').trim();

if (IS_PRODUCTION) {
  const missing = [];
  if (!DATABASE_URL) missing.push('DATABASE_URL');
  if (!REDIS_URL) missing.push('REDIS_URL');
  if (!ADMIN_USERNAME) missing.push('BOT_RISK_ADMIN_USERNAME');
  if (!/^scrypt\$[a-f0-9]{32}\$[a-f0-9]{128}$/i.test(ADMIN_PASSWORD_HASH)) {
    missing.push('BOT_RISK_ADMIN_PASSWORD_HASH');
  }
  if (!Object.keys(CLIENTS).length) missing.push('BOT_RISK_CLIENTS_JSON');
  if (!(/^10\./.test(LISTEN_HOST)
    || /^192\.168\./.test(LISTEN_HOST)
    || /^172\.(1[6-9]|2\d|3[01])\./.test(LISTEN_HOST)
    || LISTEN_HOST === '127.0.0.1'
    || LISTEN_HOST === '::1')) missing.push('RISK_LISTEN_HOST(private address)');
  if (missing.length) throw new Error(`生产环境缺少风险中心配置：${missing.join(', ')}`);
}

module.exports = {
  IS_PRODUCTION,
  PORT,
  LISTEN_HOST,
  DATABASE_URL,
  REDIS_URL,
  ADMIN_USERNAME,
  ADMIN_PASSWORD_HASH,
  CLIENTS,
  EVENT_RETENTION_DAYS,
  CROWDSEC_LAPI_URL,
  CROWDSEC_LAPI_KEY
};
