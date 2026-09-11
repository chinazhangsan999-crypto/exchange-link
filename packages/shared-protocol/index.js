'use strict';

const crypto = require('crypto');

const PROTOCOL_NAME = 'webring-control';
const PROTOCOL_VERSION = '1.0';
const HEADERS = Object.freeze({
  protocol: 'x-control-protocol',
  authorization: 'authorization',
  requestId: 'x-request-id',
  configRevision: 'x-config-revision'
});
const ERROR_CODES = Object.freeze({
  invalidRequest: 'INVALID_REQUEST',
  invalidCredential: 'INVALID_SITE_CREDENTIAL',
  unsupportedProtocol: 'UNSUPPORTED_PROTOCOL_VERSION',
  invalidSnapshot: 'INVALID_CONFIG_SNAPSHOT',
  invalidTicket: 'INVALID_OR_EXPIRED_SSO_TICKET',
  forbidden: 'FORBIDDEN',
  internal: 'INTERNAL_ERROR'
});
const CAPABILITIES = Object.freeze({
  configEtag: 'config.etag',
  nodeSnapshot: 'nodes.snapshot.v1',
  centralAds: 'ads.central.v1',
  adPolicies: 'ads.policy.v1',
  publishPage: 'publish-page.v1',
  oneTimeSso: 'sso.one-time.v1'
});
const ALL_CAPABILITIES = Object.freeze(Object.values(CAPABILITIES));
const AD_POSITIONS = Object.freeze(['banner', 'icon', 'top_float', 'bottom_float', 'icon_float']);
const AD_POLICIES = Object.freeze(['central_only', 'central_first', 'mixed', 'local_only']);

class ProtocolError extends Error {
  constructor(code, message, details = null) {
    super(message);
    this.name = 'ProtocolError';
    this.code = code;
    this.details = details;
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function parseVersion(value) {
  const match = /^(\d+)\.(\d+)$/.exec(String(value || ''));
  return match ? { major: Number(match[1]), minor: Number(match[2]), text: `${Number(match[1])}.${Number(match[2])}` } : null;
}

function isCompatibleVersion(peerVersion, supportedVersion = PROTOCOL_VERSION) {
  const peer = parseVersion(peerVersion);
  const supported = parseVersion(supportedVersion);
  return Boolean(peer && supported && peer.major === supported.major && peer.minor <= supported.minor);
}

function assertCompatibleVersion(peerVersion, supportedVersion = PROTOCOL_VERSION) {
  if (!isCompatibleVersion(peerVersion, supportedVersion)) {
    throw new ProtocolError(ERROR_CODES.unsupportedProtocol, `不支持协议版本 ${peerVersion || '未提供'}，当前支持 ${supportedVersion}`, { received: peerVersion || null, supported: supportedVersion });
  }
  return String(peerVersion);
}

function buildSiteAuthorization(credential) {
  const parsed = parseSiteCredential(credential);
  if (!parsed) throw new ProtocolError(ERROR_CODES.invalidCredential, '站点凭据格式不正确');
  return `Site ${parsed.siteId}.${parsed.secret}`;
}

function parseSiteCredential(value) {
  const match = /^(\d+)\.([A-Za-z0-9_-]{20,128})$/.exec(String(value || '').trim());
  if (!match) return null;
  return { siteId: match[1], secret: match[2], credential: `${match[1]}.${match[2]}` };
}

function parseSiteAuthorization(value) {
  const match = /^Site\s+(.+)$/i.exec(String(value || '').trim());
  return match ? parseSiteCredential(match[1]) : null;
}

function normalizeRevisionPart(value, label) {
  const text = String(value ?? '');
  if (!/^\d+$/.test(text)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, `${label}版本号不合法`);
  return text;
}

function formatRevision(revisions) {
  if (!isPlainObject(revisions)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '配置版本结构不合法');
  return [
    normalizeRevisionPart(revisions.nodes_revision, '节点'),
    normalizeRevisionPart(revisions.ads_revision, '广告'),
    normalizeRevisionPart(revisions.publish_revision, '发布页')
  ].join('-');
}

function parseRevision(value) {
  const match = /^(\d+)-(\d+)-(\d+)$/.exec(String(value || ''));
  if (!match) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '组合配置版本格式不合法');
  return { nodes_revision: match[1], ads_revision: match[2], publish_revision: match[3] };
}

function revisionEtag(revision) {
  parseRevision(revision);
  return `"cc-${revision}"`;
}

function isHttpUrl(value, allowEmpty = false) {
  if (allowEmpty && !value) return true;
  try { return ['http:', 'https:'].includes(new URL(String(value)).protocol); } catch { return false; }
}

function calculateAdIntegrity(ad) {
  const content = ad?.ad_type === 'code'
    ? String(ad.ad_code || '')
    : `${String(ad?.image_url || '')}\n${String(ad?.target_url || '')}`;
  return crypto.createHash('sha256').update(content).digest('hex');
}

function assertText(value, label, max, { allowEmpty = false } = {}) {
  if (typeof value !== 'string' || (!allowEmpty && !value.trim()) || value.length > max) {
    throw new ProtocolError(ERROR_CODES.invalidRequest, `${label}字段不合法`);
  }
  return value;
}

function assertId(value, label = 'ID') {
  if (!/^\d+$/.test(String(value || '')) || BigInt(String(value)) <= 0n) {
    throw new ProtocolError(ERROR_CODES.invalidRequest, `${label}不合法`);
  }
  return String(value);
}

function normalizeCapabilities(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter(item => typeof item === 'string' && /^[a-z0-9.-]{1,80}$/i.test(item)))].sort();
}

function createHeartbeat(input = {}) {
  return validateHeartbeat({
    protocol_version: PROTOCOL_VERSION,
    agent_version: String(input.agent_version || input.agentVersion || ''),
    applied_revision: String(input.applied_revision || input.appliedRevision || ''),
    capabilities: normalizeCapabilities(input.capabilities || ALL_CAPABILITIES),
    metadata: isPlainObject(input.metadata) ? input.metadata : {}
  });
}

function validateHeartbeat(value) {
  if (!isPlainObject(value)) throw new ProtocolError(ERROR_CODES.invalidRequest, '心跳请求必须是对象');
  assertCompatibleVersion(value.protocol_version);
  assertText(value.agent_version, 'agent_version', 80);
  if (typeof value.applied_revision !== 'string') throw new ProtocolError(ERROR_CODES.invalidRequest, 'applied_revision 必须是字符串');
  if (value.applied_revision) parseRevision(value.applied_revision);
  if (!Array.isArray(value.capabilities)) throw new ProtocolError(ERROR_CODES.invalidRequest, 'capabilities 必须是数组');
  const capabilities = normalizeCapabilities(value.capabilities);
  if (!isPlainObject(value.metadata)) throw new ProtocolError(ERROR_CODES.invalidRequest, 'metadata 必须是对象');
  const metadataBytes = Buffer.byteLength(JSON.stringify(value.metadata), 'utf8');
  if (metadataBytes > 8192) throw new ProtocolError(ERROR_CODES.invalidRequest, 'metadata 不能超过 8KB');
  return { ...value, capabilities };
}

function validateNode(node) {
  if (!isPlainObject(node)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '节点条目必须是对象');
  assertId(node.id, '节点 ID');
  assertText(node.speed_name, 'speed_name', 80);
  assertText(node.partner_name, 'partner_name', 80);
  if (!isHttpUrl(node.url)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '节点地址不合法');
  if (typeof node.enabled !== 'boolean') throw new ProtocolError(ERROR_CODES.invalidSnapshot, '节点启用状态必须是布尔值');
  if (node.sort_order !== undefined && (!Number.isSafeInteger(node.sort_order) || Math.abs(node.sort_order) > 1_000_000)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '节点排序不合法');
  return node;
}

function validateAd(ad) {
  if (!isPlainObject(ad)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '广告条目必须是对象');
  assertId(ad.id, '广告 ID');
  assertText(ad.namespace, 'namespace', 120);
  assertText(ad.title, 'title', 120);
  if (!['normal', 'code'].includes(ad.ad_type)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '广告类型不合法');
  if (!AD_POSITIONS.includes(ad.ad_position)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '广告位置不合法');
  if (!['all', 'pc', 'ios', 'non_ios', 'android', 'harmony'].includes(ad.platform)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '广告平台不合法');
  if (typeof ad.ad_code !== 'string') throw new ProtocolError(ERROR_CODES.invalidSnapshot, 'ad_code 必须是字符串');
  if (ad.ad_type === 'code' && !ad.ad_code.trim()) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '代码广告内容不能为空');
  if (ad.priority !== undefined && (!Number.isSafeInteger(ad.priority) || Math.abs(ad.priority) > 1_000_000)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '广告优先级不合法');
  if (!/^[a-f0-9]{64}$/i.test(String(ad.integrity_sha256 || ''))) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '广告完整性摘要不合法');
  if (String(ad.integrity_sha256).toLowerCase() !== calculateAdIntegrity(ad)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '广告内容与完整性摘要不一致');
  for (const field of ['image_url', 'target_url']) if (!isHttpUrl(ad[field], true)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, `${field} 地址不合法`);
  return ad;
}

function validatePublishConfig(value) {
  if (!isPlainObject(value)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '发布页配置必须是对象');
  for (const field of ['permanent_url', 'github_pages_url']) if (!isHttpUrl(value[field], true)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, `${field} 地址不合法`);
  return value;
}

function validateConfigSnapshot(value) {
  if (!isPlainObject(value)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '配置快照必须是对象');
  assertCompatibleVersion(value.protocol_version);
  assertId(value.site_id, '站点 ID');
  const expectedRevision = formatRevision(value.revisions);
  if (value.revision !== expectedRevision) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '组合版本与分项版本不一致');
  if (!Array.isArray(value.nodes) || !Array.isArray(value.ads) || !Array.isArray(value.ad_policies)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '配置快照列表字段不完整');
  value.nodes.forEach(validateNode);
  value.ads.forEach(validateAd);
  const slots = new Set();
  for (const item of value.ad_policies) {
    if (!isPlainObject(item) || !AD_POSITIONS.includes(item.slot) || !AD_POLICIES.includes(item.policy) || slots.has(item.slot)) throw new ProtocolError(ERROR_CODES.invalidSnapshot, '广告位策略不合法或重复');
    slots.add(item.slot);
  }
  validatePublishConfig(value.publish);
  return value;
}

function createSuccessEnvelope(data = null, message = '成功', status = 200) {
  return { protocol: PROTOCOL_VERSION, ok: true, code: status, message, data };
}

function createErrorEnvelope(code, message, details = null, status = 400) {
  return { protocol: PROTOCOL_VERSION, ok: false, code: status, error_code: code, message, details };
}

function validateSuccessEnvelope(value) {
  if (!isPlainObject(value)) throw new ProtocolError(ERROR_CODES.invalidRequest, '响应信封必须是对象');
  assertCompatibleVersion(value.protocol);
  if (value.ok !== true || !Number.isInteger(value.code) || value.code < 200 || value.code > 299 || typeof value.message !== 'string' || !Object.hasOwn(value, 'data')) {
    throw new ProtocolError(ERROR_CODES.invalidRequest, '成功响应信封不合法');
  }
  return value;
}

function validateErrorEnvelope(value) {
  if (!isPlainObject(value)) throw new ProtocolError(ERROR_CODES.invalidRequest, '错误响应信封必须是对象');
  assertCompatibleVersion(value.protocol);
  if (value.ok !== false || !Number.isInteger(value.code) || value.code < 400 || value.code > 599 || typeof value.error_code !== 'string' || typeof value.message !== 'string') {
    throw new ProtocolError(ERROR_CODES.invalidRequest, '错误响应信封不合法');
  }
  return value;
}

function validateHeartbeatResult(value) {
  if (!isPlainObject(value) || Number.isNaN(Date.parse(value.server_time)) || !Number.isInteger(value.heartbeat_interval_seconds) || value.heartbeat_interval_seconds < 10) {
    throw new ProtocolError(ERROR_CODES.invalidRequest, '心跳响应内容不合法');
  }
  assertCompatibleVersion(value.protocol_version);
  return value;
}

function validateSsoRedeemResult(value) {
  if (!isPlainObject(value) || !isPlainObject(value.admin)) throw new ProtocolError(ERROR_CODES.invalidTicket, 'SSO 兑换响应不合法');
  assertId(value.admin.id, '管理员 ID');
  assertText(value.admin.username, '管理员名称', 100);
  if (!/^[A-Za-z0-9_-]{24,128}$/.test(String(value.local_session_nonce || '')) || !Number.isInteger(value.expires_in) || value.expires_in < 1 || value.expires_in > 600) {
    throw new ProtocolError(ERROR_CODES.invalidTicket, 'SSO 兑换响应不合法');
  }
  return value;
}

function validateSsoRedeemRequest(value) {
  if (!isPlainObject(value) || !/^[A-Za-z0-9_-]{32,128}$/.test(String(value.ticket || ''))) throw new ProtocolError(ERROR_CODES.invalidTicket, '一次性登录票据格式不合法');
  return { ticket: String(value.ticket) };
}

module.exports = {
  PROTOCOL_NAME,
  PROTOCOL_VERSION,
  HEADERS,
  ERROR_CODES,
  CAPABILITIES,
  ALL_CAPABILITIES,
  AD_POSITIONS,
  AD_POLICIES,
  ProtocolError,
  parseVersion,
  isCompatibleVersion,
  assertCompatibleVersion,
  buildSiteAuthorization,
  parseSiteCredential,
  parseSiteAuthorization,
  formatRevision,
  parseRevision,
  revisionEtag,
  normalizeCapabilities,
  calculateAdIntegrity,
  createHeartbeat,
  validateHeartbeat,
  validateConfigSnapshot,
  createSuccessEnvelope,
  createErrorEnvelope,
  validateSuccessEnvelope,
  validateErrorEnvelope,
  validateHeartbeatResult,
  validateSsoRedeemRequest,
  validateSsoRedeemResult
};
