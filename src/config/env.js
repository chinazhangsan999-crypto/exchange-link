const crypto = require('crypto');

const PORT = Number.parseInt(process.env.PORT || '3001', 10);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error('PORT 必须是 1 到 65535 之间的有效端口号。');
}

// 生产环境绝不允许随机密钥，防止服务重启后管理员令牌和 Session 全部失效。
if (IS_PRODUCTION && (!process.env.JWT_SECRET || !process.env.SESSION_SECRET)) {
  throw new Error('生产环境启动失败：必须同时配置 JWT_SECRET 与 SESSION_SECRET 环境变量。');
}

if (!IS_PRODUCTION && (!process.env.JWT_SECRET || !process.env.SESSION_SECRET)) {
  console.warn('安全提示：当前为开发环境，正在使用临时 JWT / Session 密钥；生产部署前必须配置 JWT_SECRET 与 SESSION_SECRET。');
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
  INITIAL_ADMIN_PASSWORD
};
