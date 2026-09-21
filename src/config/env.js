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
  'GUEST_JWT_SECRET',
  'FRONTEND_PROXY_SECRET'
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
// 留空时由凭据存储层按当前运行用户的主目录选择安全路径，避免部署到
// 不同 Linux 用户后仍写入旧服务器的 /home/niaiwo。
const CONTROL_CENTER_CREDENTIAL_FILE = String(process.env.CONTROL_CENTER_CREDENTIAL_FILE || '').trim();
const CONTROL_CENTER_SYNC_INTERVAL_MS = Math.max(10_000, Math.min(10 * 60_000,
  Number.parseInt(process.env.CONTROL_CENTER_SYNC_INTERVAL_MS || '60000', 10) || 60_000));
// 后台 HTML 与 /api/admin/* 只能经该可信边缘域名进入。
const ADMIN_FRONTEND_ORIGIN = String(process.env.ADMIN_FRONTEND_ORIGIN || '').trim().replace(/\/$/, '').toLowerCase();
const FRONTEND_PROXY_SECRET = String(process.env.FRONTEND_PROXY_SECRET || '').trim();
const FRONTEND_PROXY_API_HOSTS = String(process.env.FRONTEND_PROXY_API_HOSTS || '')
  .split(',')
  .map(item => item.trim().toLowerCase().replace(/\.$/, ''))
  .filter(Boolean);
const FRONTEND_PROXY_MAX_SKEW_MS = Math.max(5_000, Math.min(5 * 60_000,
  Number.parseInt(process.env.FRONTEND_PROXY_MAX_SKEW_MS || '30000', 10) || 30_000));
const ADMIN_SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const ADMIN_SESSION_COOKIE = 'webring_admin';
const ADMIN_CSRF_COOKIE = 'webring_admin_csrf';
// 主站默认不执行第三方联盟脚本。若确有业务需要，应先迁移到独立受限域名后再显式开启。
const PUBLIC_CODE_ADS_ENABLED = process.env.PUBLIC_CODE_ADS_ENABLED === '1';
const BOT_GATE_MODES = new Set(['off', 'observe', 'enforce']);
const BOT_GATE_MODE = String(process.env.BOT_GATE_MODE || 'off').trim().toLowerCase();
if (!BOT_GATE_MODES.has(BOT_GATE_MODE)) {
  throw new Error('BOT_GATE_MODE 只能是 off、observe 或 enforce。');
}
const BOT_RISK_CENTER_URL = String(process.env.BOT_RISK_CENTER_URL || '').trim().replace(/\/$/, '');
const BOT_RISK_CLIENT_ID = String(process.env.BOT_RISK_CLIENT_ID || '').trim();
const BOT_RISK_CLIENT_SECRET = String(process.env.BOT_RISK_CLIENT_SECRET || '').trim();
const BOT_RISK_SITE_KEY = String(process.env.BOT_RISK_SITE_KEY || 'webring-main').trim();
const BOT_RISK_CENTER_ENABLED = process.env.BOT_RISK_CENTER_ENABLED === '1';
const BOT_RISK_ALLOW_PRIVATE_HTTP = process.env.BOT_RISK_ALLOW_PRIVATE_HTTP === '1';
const BOT_RISK_TIMEOUT_MS = Math.max(100, Math.min(5_000,
  Number.parseInt(process.env.BOT_RISK_TIMEOUT_MS || '800', 10) || 800));
const BOT_RISK_SYNC_INTERVAL_MS = Math.max(5_000, Math.min(5 * 60_000,
  Number.parseInt(process.env.BOT_RISK_SYNC_INTERVAL_MS || '15000', 10) || 15_000));
const EDGE_ACCESS_SECRET = String(process.env.EDGE_ACCESS_SECRET || '').trim();
const BROWSER_ACCESS_TTL_MS = Math.max(15 * 60_000, Math.min(24 * 60 * 60_000,
  Number.parseInt(process.env.BROWSER_ACCESS_TTL_MS || String(4 * 60 * 60_000), 10)
    || 4 * 60 * 60_000));

if (BOT_RISK_CENTER_ENABLED) {
  let riskCenterUrl;
  try { riskCenterUrl = new URL(BOT_RISK_CENTER_URL); } catch { riskCenterUrl = null; }
  const hostname = riskCenterUrl?.hostname || '';
  const privateHttp = BOT_RISK_ALLOW_PRIVATE_HTTP
    && riskCenterUrl?.protocol === 'http:'
    && (/^10\./.test(hostname)
      || /^192\.168\./.test(hostname)
      || /^172\.(1[6-9]|2\d|3[01])\./.test(hostname)
      || hostname === '127.0.0.1'
      || hostname === 'localhost');
  if (IS_PRODUCTION && riskCenterUrl?.protocol !== 'https:' && !privateHttp) {
    throw new Error('生产环境 BOT_RISK_CENTER_URL 必须使用 HTTPS，或显式允许 RFC1918 私网 HTTP。');
  }
  if (!BOT_RISK_CENTER_URL || !/^[A-Za-z0-9_-]{3,64}$/.test(BOT_RISK_CLIENT_ID)
    || BOT_RISK_CLIENT_SECRET.length < 32 || !/^[A-Za-z0-9_-]{3,64}$/.test(BOT_RISK_SITE_KEY)) {
    throw new Error('启用机器人风险中心后，必须配置有效 URL、client id、site key 和至少 32 字符的 secret。');
  }
}

if (BOT_GATE_MODE !== 'off' && EDGE_ACCESS_SECRET.length < 32) {
  throw new Error('BOT_GATE_MODE=observe 或 enforce 时必须配置至少 32 字符的 EDGE_ACCESS_SECRET。');
}

const ADMIN_ORIGIN_PATTERN = IS_PRODUCTION ? /^https:\/\/[^/]+$/i : /^https?:\/\/[^/]+$/i;
if (ADMIN_FRONTEND_ORIGIN && !ADMIN_ORIGIN_PATTERN.test(ADMIN_FRONTEND_ORIGIN)) {
  throw new Error('ADMIN_FRONTEND_ORIGIN 必须是有效 Origin；生产环境仅允许 HTTPS。');
}

if (FRONTEND_PROXY_SECRET && FRONTEND_PROXY_SECRET.length < 32) {
  throw new Error('FRONTEND_PROXY_SECRET 长度不得少于 32 位。');
}

if (CONTROL_CENTER_ENABLED) {
  // 地址和凭据也可由后台写入权限 600 的凭据文件；环境变量存在时仍严格校验，
  // 但不再强迫运维把已经落入安全文件的密钥重复保存在 PM2 环境中。
  if (CONTROL_CENTER_URL && !/^https:\/\//i.test(CONTROL_CENTER_URL)) {
    throw new Error('启用总后台后，CONTROL_CENTER_URL 必须是 HTTPS 地址。');
  }
  if (CONTROL_CENTER_SITE_CREDENTIAL && !/^\d+\.[A-Za-z0-9_-]{20,128}$/.test(CONTROL_CENTER_SITE_CREDENTIAL)) {
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
  CONTROL_CENTER_CREDENTIAL_FILE,
  CONTROL_CENTER_SYNC_INTERVAL_MS,
  ADMIN_FRONTEND_ORIGIN,
  FRONTEND_PROXY_SECRET,
  FRONTEND_PROXY_API_HOSTS,
  FRONTEND_PROXY_MAX_SKEW_MS,
  ADMIN_SESSION_TTL_MS,
  ADMIN_SESSION_COOKIE,
  ADMIN_CSRF_COOKIE,
  PUBLIC_CODE_ADS_ENABLED,
  BOT_GATE_MODE,
  BOT_RISK_CENTER_ENABLED,
  BOT_RISK_ALLOW_PRIVATE_HTTP,
  BOT_RISK_CENTER_URL,
  BOT_RISK_CLIENT_ID,
  BOT_RISK_CLIENT_SECRET,
  BOT_RISK_SITE_KEY,
  BOT_RISK_TIMEOUT_MS,
  BOT_RISK_SYNC_INTERVAL_MS,
  EDGE_ACCESS_SECRET,
  BROWSER_ACCESS_TTL_MS
};
