const net = require('net');
const { getDomain } = require('tldts');

/** 安全解析 URL / Referer 的主机名，非法值与空值均返回空字符串。 */
function parseHostname(value) {
  if (!value) return '';
  try {
    return new URL(value).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
}

/**
 * 返回可注册主域名（例如 blog.example.co.uk -> example.co.uk）。
 * IP、localhost 等不适用公共后缀规则时保留原主机名。
 */
function normalizeRegisteredDomain(hostname) {
  const normalizedHost = String(hostname || '')
    .trim()
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/^www\./, '');
  if (!normalizedHost) return '';
  return getDomain(normalizedHost, { allowPrivateDomains: true }) || normalizedHost;
}

/** 统一解析友链地址：补全协议、保留跳转 URL，并取得可注册主域名。 */
function normalizePartnerUrl(value) {
  let raw = String(value || '').trim();
  if (!raw) throw new Error('网站地址不能为空');
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;

  const parsed = new URL(raw);
  if (!/^https?:$/.test(parsed.protocol)) throw new Error('网站地址仅支持 HTTP 或 HTTPS');
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname) throw new Error('无法从网站地址识别域名');

  return {
    url: parsed.toString().replace(/\/$/, ''),
    domain: normalizeRegisteredDomain(hostname)
  };
}

/** 来路标记只去除空白，保留大小写；URL 路径和查询参数可能区分大小写。 */
function normalizeSourceMarker(value) {
  return String(value || '').trim();
}

/** 已登记根域名匹配自身或任意子域名，避免 evil-example.com 等伪匹配。 */
function matchesPartnerDomain(hostname, registeredDomain) {
  const host = String(hostname || '').toLowerCase().replace(/^www\./, '');
  const domain = String(registeredDomain || '').toLowerCase().replace(/^www\./, '');
  return Boolean(host && domain && (host === domain || host.endsWith(`.${domain}`)));
}

function expandIpv6Hextets(value) {
  let address = String(value || '').trim().toLowerCase();
  const zoneIndex = address.indexOf('%');
  if (zoneIndex >= 0) address = address.slice(0, zoneIndex);
  if (net.isIP(address) !== 6) return null;

  // 将 IPv6 尾部的点分 IPv4 转换成两个十六进制块，再统一展开 ::。
  const ipv4Tail = address.match(/(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1];
  if (ipv4Tail) {
    const octets = ipv4Tail.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    address = `${address.slice(0, -ipv4Tail.length)}${high}:${low}`;
  }

  const halves = address.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  const blocks = halves.length === 1
    ? left
    : [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];

  if (blocks.length !== 8) return null;
  return blocks.map(block => Number.parseInt(block || '0', 16).toString(16));
}

/**
 * 获取 Express 根据 trust proxy 配置解析后的客户端 IP，并将 IPv6 聚合至 /64。
 * 禁止直接读取客户端可伪造的转发请求头。
 */
function getClientIp(req) {
  let ip = String(req.ip || req.socket?.remoteAddress || '').trim();
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  const zoneIndex = ip.indexOf('%');
  if (zoneIndex >= 0) ip = ip.slice(0, zoneIndex);

  if (net.isIP(ip) === 4) return ip;
  const blocks = expandIpv6Hextets(ip);
  if (!blocks) return ip;

  // IPv4-mapped IPv6 必须还原成 IPv4，避免所有 IPv4 被错误聚合到 ::/64。
  if (blocks.slice(0, 5).every(block => block === '0') && blocks[5] === 'ffff') {
    const high = Number.parseInt(blocks[6], 16);
    const low = Number.parseInt(blocks[7], 16);
    return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
  }

  return `${blocks.slice(0, 4).join(':')}::/64`;
}

/** 判断 IPv4/IPv6 是否为回环、私网、链路本地或云元数据等敏感地址。 */
function isSensitiveNetworkIp(value) {
  const ip = String(value || '').toLowerCase().replace(/^::ffff:/, '');
  if (net.isIP(ip) === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) ||
      (a >= 224) || ip === '169.254.169.254';
  }
  if (net.isIP(ip) === 6) {
    return ip === '::' || ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') ||
      ip.startsWith('fe8') || ip.startsWith('fe9') || ip.startsWith('fea') || ip.startsWith('feb') ||
      ip.startsWith('::ffff:127.') || ip.startsWith('::ffff:10.') || ip.startsWith('::ffff:192.168.') || ip.startsWith('::ffff:169.254.');
  }
  return true;
}

module.exports = {
  getClientIp,
  parseHostname,
  normalizeRegisteredDomain,
  normalizePartnerUrl,
  normalizeSourceMarker,
  matchesPartnerDomain,
  isSensitiveNetworkIp
};
