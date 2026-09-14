const crypto = require('crypto');
const fs = require('fs');

const PORT = Number.parseInt(process.env.PORT || '3001', 10);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error('PORT 必须是 1 到 65535 之间的有效端口号。');
}

// 生产环境绝不允许实际使用的密钥回退为进程级随机值；否则重启会使
// 管理员令牌、访客验证令牌和 Session 全部失效。
const REQUIRED_PRODUCTION_SECRETS = [
  'SESSION_SECRET',
  'ADMIN_JWT_SECRET',
  'GUEST_JWT_SECRET'
];
const missingProductionSecrets = REQUIRED_PRODUCTION_SECRETS.filter(key => !process.env[key]);

if (IS_PRODUCTION && missingProductionSecrets.length) {
  throw new Error(`生产环境启动失败：缺少 ${missingProductionSecrets.join(', ')} 环境变量。`);
}

if (!IS_PRODUCTION && missingProductionSecrets.length) {
  console.warn('安全提示：当前为开发环境，正在使用临时 Session / Admin JWT / Guest JWT 密钥；生产部署前必须配置它们。');
}

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
// 管理员与访客令牌必须使用不同的签名密钥，禁止跨签发上下文复用。
// 未显式配置时使用进程级随机密钥；生产部署仍建议配置持久化环境变量，
// 否则服务重启后对应令牌会立即失效。
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || crypto.randomBytes(32).toString('hex');
const GUEST_JWT_SECRET = process.env.GUEST_JWT_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
// 保留旧导出供兼容，但新滑块与访客令牌统一使用 GUEST_JWT_SECRET。
const VERIFY_HMAC_SECRET = process.env.VERIFY_HMAC_SECRET || GUEST_JWT_SECRET;
const TRUSTED_PROXIES = String(process.env.TRUSTED_PROXIES || '')
  .split(',')
  .map(item => item.trim())
  .filter(Boolean);
const TRAFFIC_DEBUG = process.env.TRAFFIC_DEBUG !== '0';
const INITIAL_ADMIN_PASSWORD = String(process.env.INITIAL_ADMIN_PASSWORD || '');
const IP_INTELLIGENCE_CREDENTIAL_FILE = String(process.env.IP_INTELLIGENCE_CREDENTIAL_FILE || '').trim();
let ipIntelligenceFileCredentials = {};
if (IP_INTELLIGENCE_CREDENTIAL_FILE) {
  try {
    ipIntelligenceFileCredentials = JSON.parse(fs.readFileSync(IP_INTELLIGENCE_CREDENTIAL_FILE, 'utf8'));
  } catch (error) {
    throw new Error(`无法读取 IP 情报客户端凭据文件：${error.message}`);
  }
}
const IP_INTELLIGENCE_BASE_URL = String(process.env.IP_INTELLIGENCE_BASE_URL || 'https://ip.chinazhangsan.ccwu.cc').trim().replace(/\/$/, '');
const IP_INTELLIGENCE_CLIENT_ID = String(process.env.IP_INTELLIGENCE_CLIENT_ID
  || ipIntelligenceFileCredentials.client_id || ipIntelligenceFileCredentials.clientId || 'nav-main').trim();
const IP_INTELLIGENCE_CLIENT_SECRET = String(process.env.IP_INTELLIGENCE_CLIENT_SECRET
  || ipIntelligenceFileCredentials.secret || '').trim();
const IP_INTELLIGENCE_ENABLED = process.env.IP_INTELLIGENCE_ENABLED !== '0'
  && Boolean(IP_INTELLIGENCE_BASE_URL && IP_INTELLIGENCE_CLIENT_ID && IP_INTELLIGENCE_CLIENT_SECRET);
const IP_INTELLIGENCE_TIMEOUT_MS = Math.max(1000, Math.min(10_000,
  Number.parseInt(process.env.IP_INTELLIGENCE_TIMEOUT_MS || '3000', 10) || 3000));
const IP_INTELLIGENCE_BATCH_SIZE = Math.max(1, Math.min(100,
  Number.parseInt(process.env.IP_INTELLIGENCE_BATCH_SIZE || '50', 10) || 50));
const CONTROL_CENTER_ENABLED = process.env.CONTROL_CENTER_ENABLED === '1';
const CONTROL_CENTER_URL = String(process.env.CONTROL_CENTER_URL || '').trim().replace(/\/$/, '');
const CONTROL_CENTER_SITE_CREDENTIAL = String(process.env.CONTROL_CENTER_SITE_CREDENTIAL || '').trim();
const CONTROL_CENTER_SYNC_INTERVAL_MS = Math.max(10_000, Math.min(10 * 60_000,
  Number.parseInt(process.env.CONTROL_CENTER_SYNC_INTERVAL_MS || '60000', 10) || 60_000));
const PUBLIC_FRONTEND_MODE = String(process.env.PUBLIC_FRONTEND_MODE || 'embedded').trim().toLowerCase();
const FRONTEND_PROXY_SECRET = String(process.env.FRONTEND_PROXY_SECRET || '').trim();
const FRONTEND_PROXY_MAX_SKEW_MS = Math.max(5_000, Math.min(5 * 60_000,
  Number.parseInt(process.env.FRONTEND_PROXY_MAX_SKEW_MS || '30000', 10) || 30_000));

if (!['embedded', 'separated'].includes(PUBLIC_FRONTEND_MODE)) {
  throw new Error('PUBLIC_FRONTEND_MODE 仅支持 embedded 或 separated。');
}

if (FRONTEND_PROXY_SECRET && FRONTEND_PROXY_SECRET.length < 32) {
  throw new Error('FRONTEND_PROXY_SECRET 长度不得少于 32 位。');
}

if (PUBLIC_FRONTEND_MODE === 'separated' && FRONTEND_PROXY_SECRET.length < 32) {
  throw new Error('启用前后端分离模式前，必须配置不少于 32 位的 FRONTEND_PROXY_SECRET。');
}

if (CONTROL_CENTER_ENABLED) {
  if (!/^https:\/\//i.test(CONTROL_CENTER_URL)) {
    throw new Error('启用总后台后，CONTROL_CENTER_URL 必须是 HTTPS 地址。');
  }
  if (!/^\d+\.[A-Za-z0-9_-]{20,128}$/.test(CONTROL_CENTER_SITE_CREDENTIAL)) {
    throw new Error('启用总后台后，必须配置有效的 CONTROL_CENTER_SITE_CREDENTIAL。');
  }
}

if (INITIAL_ADMIN_PASSWORD && INITIAL_ADMIN_PASSWORD.length < 8) {
  throw new Error('INITIAL_ADMIN_PASSWORD 长度不得少于 8 位。');
}

module.exports = {
  PORT,
  IS_PRODUCTION,
  JWT_SECRET,
  ADMIN_JWT_SECRET,
  GUEST_JWT_SECRET,
  SESSION_SECRET,
  VERIFY_HMAC_SECRET,
  TRUSTED_PROXIES,
  TRAFFIC_DEBUG,
  INITIAL_ADMIN_PASSWORD,
  IP_INTELLIGENCE_ENABLED,
  IP_INTELLIGENCE_CREDENTIAL_FILE,
  IP_INTELLIGENCE_BASE_URL,
  IP_INTELLIGENCE_CLIENT_ID,
  IP_INTELLIGENCE_CLIENT_SECRET,
  IP_INTELLIGENCE_TIMEOUT_MS,
  IP_INTELLIGENCE_BATCH_SIZE,
  CONTROL_CENTER_ENABLED,
  CONTROL_CENTER_URL,
  CONTROL_CENTER_SITE_CREDENTIAL,
  CONTROL_CENTER_SYNC_INTERVAL_MS,
  PUBLIC_FRONTEND_MODE,
  FRONTEND_PROXY_SECRET,
  FRONTEND_PROXY_MAX_SKEW_MS
};
