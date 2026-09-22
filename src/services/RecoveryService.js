'use strict';

const crypto = require('crypto');
const axios = require('axios');
const RecoveryModel = require('../models/RecoveryModel');
const CloudflareFrontendModel = require('../models/CloudflareFrontendModel');
const RecoveryCredentialStore = require('./RecoveryCredentialStore');
const IntegrationCredentialStore = require('./IntegrationCredentialStore');
const DnsPublisherService = require('./DnsPublisherService');
const { assertSafeBacklinkUrl, createPinnedAxiosConfig } = require('./InspectionService');
const { runPromisePool } = require('../utils/asyncPool');

const HEALTH_PATH = '/.well-known/route-health.gif';
const GIF_1X1 = Buffer.from('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==', 'base64');
const DOH_RESOLVERS = Object.freeze([
  { id: 'dnspod', label: 'DNSPod', endpoint: 'https://doh.pub/dns-query' },
  { id: 'alidns', label: 'AliDNS', endpoint: 'https://dns.alidns.com/dns-query' },
  { id: 'cloudflare', label: 'Cloudflare', endpoint: 'https://cloudflare-dns.com/dns-query' },
  { id: 'google', label: 'Google Public DNS', endpoint: 'https://dns.google/dns-query' },
  { id: 'quad9-unfiltered', label: 'Quad9 No-block', endpoint: 'https://dns10.quad9.net/dns-query' },
  { id: 'adguard-unfiltered', label: 'AdGuard Unfiltered', endpoint: 'https://unfiltered.adguard-dns.com/dns-query' },
  { id: 'mullvad', label: 'Mullvad DNS', endpoint: 'https://dns.mullvad.net/dns-query' },
  { id: 'controld-free', label: 'Control D Free', endpoint: 'https://freedns.controld.com/p0' }
]);
const TXT_DATA_SIZE = 180;
const PORTABLE_TXT_BYTES = 240;
const MAX_ENCODED_SIZE = 4096;

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function normalizeOrigin(value) {
  const raw = String(value || '').trim();
  if (raw.length > 200) throw new Error('恢复线路地址不能超过 200 个字符');
  const parsed = new URL(raw);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash || parsed.search) {
    throw new Error('恢复线路必须是无认证、无参数的 HTTPS 地址');
  }
  if (parsed.port && parsed.port !== '443') throw new Error('恢复线路不允许使用非标准端口');
  if (parsed.pathname !== '/' && parsed.pathname !== '') throw new Error('恢复线路只能填写域名 Origin，不能包含路径');
  return parsed.origin;
}

function normalizeHttpsUrl(value, label) {
  const text = String(value || '').trim();
  if (!text) return '';
  const parsed = new URL(text);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) throw new Error(`${label}必须使用无认证的 HTTPS 地址`);
  return parsed.href;
}

function normalizeDnsName(value, label = 'DNS 名称') {
  const text = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!/^(?:_[a-z0-9-]+\.)?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(text) || !text.includes('.')) {
    throw new Error(`${label}格式不正确`);
  }
  return text;
}

function validateDomainInput(input = {}) {
  const title = String(input.title || '').trim();
  if (!title || title.length > 80) throw new Error('线路名称需为 1 到 80 个字符');
  return {
    title,
    url: normalizeOrigin(input.url),
    priority: Math.max(-100000, Math.min(100000, Number.parseInt(input.priority, 10) || 0)),
    status: ['1', 1, true, 'true', 'on'].includes(input.status) ? 1 : 0
  };
}

function validateBootstrapInput(input = {}) {
  const label = String(input.label || '').trim();
  if (!label || label.length > 80) throw new Error('Bootstrap 名称需为 1 到 80 个字符');
  const zoneName = normalizeDnsName(input.zoneName, 'DNS Zone');
  const recordName = normalizeDnsName(input.recordName, 'TXT 记录名');
  if (!(recordName === zoneName || recordName.endsWith(`.${zoneName}`))) throw new Error('TXT 记录必须位于所填写的 DNS Zone 内');
  const providerId = String(input.providerId || 'cloudflare').trim().toLowerCase();
  if (!['cloudflare', 'desec', 'cloudns', 'route53', 'dnspod', 'aliyun', 'baidu', 'volcengine', 'he'].includes(providerId)) throw new Error('请选择受支持的权威 DNS 托管商');
  const shareRole = String(input.shareRole || 'LEGACY').trim().toUpperCase();
  if (!['A', 'B', 'LEGACY'].includes(shareRole)) throw new Error('TXT 分片角色只能是 A、B 或旧版兼容');
  const publishMode = String(input.publishMode || (providerId === 'cloudflare' ? 'automatic' : 'manual')).trim().toLowerCase();
  if (!['automatic', 'manual'].includes(publishMode)) throw new Error('发布方式不正确');
  const capability = DnsPublisherService.providerCapabilities().find(item => item.id === providerId);
  if (publishMode === 'automatic' && !capability?.automaticPublish) throw new Error('该 DNS 服务商当前不支持 API 自动发布');
  const dnsChannelId = Number.parseInt(input.dnsChannelId, 10);
  return {
    label,
    zoneName,
    recordName,
    isPrimary: ['1', 1, true, 'true', 'on'].includes(input.isPrimary) ? 1 : 0,
    status: ['1', 1, true, 'true', 'on'].includes(input.status) ? 1 : 0,
    sortOrder: Math.max(-100000, Math.min(100000, Number.parseInt(input.sortOrder, 10) || 0)),
    providerId,
    shareRole,
    publishMode,
    dnsChannelId: Number.isInteger(dnsChannelId) && dnsChannelId > 0 ? dnsChannelId : null,
    providerZoneId: String(input.providerZoneId || '').trim()
  };
}

async function validateBootstrapConfiguration(input = {}, profileId = 1) {
  const normalized = validateBootstrapInput(input);
  if (normalized.publishMode !== 'automatic') return { ...normalized, dnsChannelId: null, providerZoneId: '' };
  if (!normalized.dnsChannelId) throw new Error('API 自动发布必须选择 DNS API 通道');
  const channel = await RecoveryModel.getDnsChannel(normalized.dnsChannelId, profileId);
  if (!channel || Number(channel.status) !== 1) throw new Error('所选 DNS API 通道不存在或已停用');
  if (channel.provider_id !== normalized.providerId) throw new Error('DNS API 通道与权威 DNS 服务商不匹配');
  if (!credentialConfigured(channel.provider_id, credentialsForChannel(channel))) throw new Error('所选 DNS API 通道尚未配置完整凭据');
  return normalized;
}

function publicKeyPemToSpkiBase64(pem) {
  return String(pem || '').replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
}

function keyPair() {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const suffix = crypto.randomBytes(4).toString('hex');
  return {
    keyId: `recovery-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${suffix}`,
    publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    createdAt: new Date().toISOString()
  };
}

async function ensureCurrentKey(profileId = 1) {
  const settings = await RecoveryModel.getSettings(profileId);
  const stored = RecoveryCredentialStore.signingKeys(profileId);
  if (settings.public_key_id && settings.public_key && stored.current?.privateKey) return stored.current;
  const generated = keyPair();
  await RecoveryCredentialStore.saveSigningKeys({ ...stored, current: generated }, profileId);
  await RecoveryModel.saveKeyState({ public_key_id: generated.keyId, public_key: generated.publicKey }, profileId);
  await RecoveryModel.addAudit('key.generate.current', { keyId: generated.keyId }, true, '', profileId);
  return generated;
}

async function generateNextKey(profileId = 1) {
  await ensureCurrentKey(profileId);
  const stored = RecoveryCredentialStore.signingKeys(profileId);
  const generated = keyPair();
  await RecoveryCredentialStore.saveSigningKeys({ current: stored.current, next: generated }, profileId);
  await RecoveryModel.saveKeyState({ next_public_key_id: generated.keyId, next_public_key: generated.publicKey }, profileId);
  await RecoveryModel.addAudit('key.generate.next', { keyId: generated.keyId }, true, '', profileId);
  return keyStatus(profileId);
}

async function promoteNextKey(profileId = 1) {
  const stored = RecoveryCredentialStore.signingKeys(profileId);
  if (!stored.next?.privateKey) throw new Error('尚未生成下一代密钥');
  const [settings, published] = await Promise.all([
    RecoveryModel.getSettings(profileId),
    RecoveryModel.getLatestPublishedRelease(profileId)
  ]);
  if (!published) throw new Error('请先发布包含下一代公钥的过渡版本，再提升密钥');
  const envelope = envelopeForRelease(published);
  const currentKeys = [{ keyId: settings.public_key_id, publicKey: settings.public_key }];
  const nextIsTrusted = Array.isArray(envelope.trustedKeys)
    && envelope.trustedKeys.some(item => item.keyId === stored.next.keyId && item.spki);
  if (!verifyEnvelope(envelope, currentKeys) || !nextIsTrusted) {
    throw new Error('当前正式版本尚未安全发布下一代公钥，请先生成并发布过渡版本');
  }
  await RecoveryCredentialStore.saveSigningKeys({ current: stored.next, next: null }, profileId);
  await RecoveryModel.saveKeyState({
    public_key_id: stored.next.keyId,
    public_key: stored.next.publicKey,
    next_public_key_id: '',
    next_public_key: ''
  }, profileId);
  await RecoveryModel.addAudit('key.promote', { keyId: stored.next.keyId }, true, '', profileId);
  return keyStatus(profileId);
}

async function keyStatus(profileId = 1) {
  const settings = await RecoveryModel.getSettings(profileId);
  const stored = RecoveryCredentialStore.signingKeys(profileId);
  return {
    currentKeyId: settings.public_key_id || '',
    currentPublicKey: settings.public_key || '',
    currentPrivateKeyConfigured: Boolean(stored.current?.privateKey),
    nextKeyId: settings.next_public_key_id || '',
    nextPublicKey: settings.next_public_key || '',
    nextPrivateKeyConfigured: Boolean(stored.next?.privateKey)
  };
}

async function updateSettings(input = {}, profileId = 1) {
  const recoveryEmail = String(input.recovery_email || '').trim();
  if (recoveryEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recoveryEmail)) throw new Error('恢复专用邮箱格式不正确');
  const normalized = {
    enabled: ['1', 1, true, 'true', 'on'].includes(input.enabled) ? 1 : 0,
    recovery_email: recoveryEmail,
    recovery_publish_url: normalizeHttpsUrl(input.recovery_publish_url, '恢复专用发布页'),
    recovery_contact: String(input.recovery_contact || '').trim().slice(0, 300),
    recovery_message: String(input.recovery_message || '').trim().slice(0, 1000),
    found_message: String(input.found_message || '').trim().slice(0, 500),
    manifest_valid_days: Math.max(7, Math.min(365, Number.parseInt(input.manifest_valid_days, 10) || 90)),
    max_domains: Math.max(1, Math.min(10, Number.parseInt(input.max_domains, 10) || 10)),
    probe_timeout_ms: Math.max(1000, Math.min(10000, Number.parseInt(input.probe_timeout_ms, 10) || 3000)),
    probe_concurrency: Math.max(1, Math.min(3, Number.parseInt(input.probe_concurrency, 10) || 3))
  };
  const saved = await RecoveryModel.updateSettings(normalized, profileId);
  await RecoveryModel.addAudit('settings.update', { enabled: saved.enabled }, true, '', profileId);
  return saved;
}

async function probeDomain(domain, options = {}) {
  const origin = normalizeOrigin(domain.url || domain);
  const timeoutMs = Math.max(1000, Math.min(10000, Number(options.timeoutMs) || 3000));
  const target = `${origin}${HEALTH_PATH}?recovery=${crypto.randomUUID()}&t=${Date.now()}`;
  const started = Date.now();
  try {
    const safeTarget = await assertSafeBacklinkUrl(target);
    const pinned = createPinnedAxiosConfig(safeTarget, {
      'User-Agent': 'NavigationRecoveryProbe/1.0',
      Accept: 'image/gif'
    });
    const response = await axios.request({
      ...pinned,
      method: 'GET',
      timeout: timeoutMs,
      maxRedirects: 0,
      responseType: 'arraybuffer',
      maxContentLength: 1024,
      validateStatus: status => status === 200
    });
    const body = Buffer.from(response.data || []);
    const healthy = body.equals(GIF_1X1) || (body.length >= 10 && body.subarray(0, 6).toString('ascii').startsWith('GIF'));
    if (!healthy) throw new Error('健康图片内容不是有效的 1×1 GIF');
    return { healthy: true, elapsedMs: Math.max(1, Date.now() - started), checkedAt: new Date().toISOString(), error: '' };
  } catch (error) {
    return { healthy: false, elapsedMs: Math.max(1, Date.now() - started), checkedAt: new Date().toISOString(), error: String(error.message || '检测失败') };
  }
}

async function probeAndSave(id, profileId = 1) {
  const domain = await RecoveryModel.getDomain(id, profileId);
  if (!domain) throw new Error('恢复线路不存在');
  const settings = await RecoveryModel.getSettings(profileId);
  let result = await probeDomain(domain, { timeoutMs: settings.probe_timeout_ms });
  if (!result.healthy) result = await probeDomain(domain, { timeoutMs: settings.probe_timeout_ms });
  await RecoveryModel.saveProbeResult(id, result);
  await RecoveryModel.addAudit('domain.probe', { id, url: domain.url, healthy: result.healthy }, result.healthy, result.error, profileId);
  return { ...domain, ...result };
}

async function probeAll(profileId = 1) {
  const settings = await RecoveryModel.getSettings(profileId);
  const domains = await RecoveryModel.listDomains({ enabledOnly: true, profileId });
  const settled = await runPromisePool(domains, settings.probe_concurrency, async domain => probeAndSave(domain.id, profileId), settings.probe_timeout_ms * 3);
  const results = settled.map((item, index) => item.status === 'fulfilled' ? item.value : ({
    ...domains[index], healthy: false, error: String(item.reason?.message || item.reason || '检测任务失败')
  }));
  return { total: results.length, healthy: results.filter(item => item.healthy).length, failed: results.filter(item => !item.healthy).length, results };
}

function signPayload(payload, privateKey) {
  return crypto.sign('sha256', Buffer.from(stableStringify(payload)), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  }).toString('base64url');
}

function verifyEnvelope(envelope, publicKeys) {
  if (!envelope || typeof envelope !== 'object' || !envelope.signature || !envelope.keyId) return false;
  const payload = { ...envelope };
  delete payload.signature;
  const key = publicKeys.find(item => item.keyId === envelope.keyId)?.publicKey;
  if (!key) return false;
  try {
    return crypto.verify('sha256', Buffer.from(stableStringify(payload)), {
      key,
      dsaEncoding: 'ieee-p1363'
    }, Buffer.from(envelope.signature, 'base64url'));
  } catch { return false; }
}

async function createDraft({ sourceReleaseId = null, profileId = 1 } = {}) {
  const [settings, domains] = await Promise.all([
    RecoveryModel.getSettings(profileId),
    RecoveryModel.listDomains({ enabledOnly: true, profileId })
  ]);
  if (!domains.length) throw new Error('至少需要一条已启用的恢复线路');
  if (domains.length > settings.max_domains) throw new Error(`已启用线路超过后台限制（最多 ${settings.max_domains} 条）`);
  const key = await ensureCurrentKey(profileId);
  const generation = await RecoveryModel.nextGeneration(profileId);
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + Number(settings.manifest_valid_days) * 86400;
  const releaseId = `${generation}-${crypto.randomBytes(8).toString('hex')}`;
  const payloadCore = {
    schema: 3,
    project: settings.project_id,
    generation,
    releaseId,
    issuedAt,
    expiresAt,
    domains: domains.map(item => ({ title: item.title, url: item.url, priority: Number(item.priority) })),
    trustedKeys: [
      { keyId: settings.public_key_id || key.keyId, spki: publicKeyPemToSpkiBase64(settings.public_key || key.publicKey) },
      { keyId: settings.next_public_key_id, spki: publicKeyPemToSpkiBase64(settings.next_public_key) }
    ].filter(item => item.keyId && item.spki),
    keyId: key.keyId
  };
  const payload = { ...payloadCore, manifestHash: crypto.createHash('sha256').update(stableStringify(payloadCore)).digest('hex') };
  const payloadJson = stableStringify(payload);
  const release = await RecoveryModel.createRelease({
    generation,
    payloadJson,
    payloadHash: crypto.createHash('sha256').update(payloadJson).digest('hex'),
    signature: signPayload(payload, key.privateKey),
    keyId: key.keyId,
    status: 'draft',
    issuedAt: new Date(issuedAt * 1000).toISOString(),
    expiresAt: new Date(expiresAt * 1000).toISOString(),
    sourceReleaseId
  }, profileId);
  await RecoveryModel.addAudit('release.draft', { id: release.id, generation }, true, '', profileId);
  return serializeRelease(release);
}

function envelopeForRelease(release) {
  return { ...JSON.parse(release.payload_json), signature: release.signature };
}

function serializeRelease(release) {
  if (!release) return null;
  return { ...release, envelope: envelopeForRelease(release), payload_json: undefined, signature: undefined };
}

function chunkEnvelope(envelope) {
  const encoded = Buffer.from(JSON.stringify(envelope)).toString('base64url');
  if (encoded.length > MAX_ENCODED_SIZE) throw new Error('恢复清单编码后超过 4KB，无法安全发布到 DNS TXT');
  const parts = [];
  const total = Math.ceil(encoded.length / TXT_DATA_SIZE);
  if (total > 50) throw new Error('恢复清单 TXT 分片过多');
  const set = `${envelope.generation}-${crypto.createHash('sha256').update(encoded).digest('hex').slice(0, 8)}`;
  for (let index = 0; index < total; index += 1) {
    parts.push(`r1;set=${set};part=${index + 1}/${total};data=${encoded.slice(index * TXT_DATA_SIZE, (index + 1) * TXT_DATA_SIZE)}`);
  }
  return { set, parts };
}

function assertPortableTxt(parts, byteLimit = PORTABLE_TXT_BYTES) {
  for (const value of parts) {
    const bytes = Buffer.byteLength(value, 'utf8');
    if (bytes > byteLimit) throw new Error(`TXT 单条内容为 ${bytes} 字节，超过托管商安全上限 ${byteLimit} 字节`);
  }
  return parts;
}

function chunkShare(envelope, role, shareBytes, byteLimit = PORTABLE_TXT_BYTES) {
  const encoded = Buffer.from(shareBytes).toString('base64url');
  const set = `${envelope.generation}-${envelope.releaseId}-${envelope.manifestHash.slice(0, 12)}`;
  const header = index => `r2;set=${set};role=${role};part=${index}/999;data=`;
  const dataSize = Math.max(32, Math.min(140, byteLimit - Buffer.byteLength(header(999), 'utf8')));
  const total = Math.ceil(encoded.length / dataSize);
  if (total < 1 || total > 50) throw new Error('恢复清单 TXT 分片过多');
  const parts = Array.from({ length: total }, (_, index) => `r2;set=${set};role=${role};part=${index + 1}/${total};data=${encoded.slice(index * dataSize, (index + 1) * dataSize)}`);
  return { set, role, parts: assertPortableTxt(parts, byteLimit) };
}

function deterministicShare(length, secret, context) {
  if (!secret) return crypto.randomBytes(length);
  const blocks = [];
  for (let counter = 0; Buffer.concat(blocks).length < length; counter += 1) {
    blocks.push(crypto.createHmac('sha256', secret).update(`${context}:${counter}`).digest());
  }
  return Buffer.concat(blocks).subarray(0, length);
}

function shardEnvelope(envelope, byteLimit = PORTABLE_TXT_BYTES, secret = '') {
  const manifest = Buffer.from(JSON.stringify(envelope));
  if (manifest.length > MAX_ENCODED_SIZE) throw new Error('恢复清单超过 4KB，无法安全发布到 DNS TXT');
  const shareA = deterministicShare(manifest.length, secret, `${envelope.project}:${envelope.generation}:${envelope.releaseId}:${envelope.manifestHash}`);
  const shareB = Buffer.alloc(manifest.length);
  for (let index = 0; index < manifest.length; index += 1) shareB[index] = shareA[index] ^ manifest[index];
  return { A: chunkShare(envelope, 'A', shareA, byteLimit), B: chunkShare(envelope, 'B', shareB, byteLimit) };
}

function parseTxtValue(input) {
  let text = String(input || '').trim();
  if (text.startsWith('"') && text.endsWith('"')) text = text.slice(1, -1);
  return text.replace(/"\s*"/g, '').replace(/\\"/g, '"');
}

function assembleTxt(values) {
  const sets = new Map();
  for (const raw of values) {
    const text = parseTxtValue(raw);
    const match = /^r1;set=([^;]+);part=(\d+)\/(\d+);data=([A-Za-z0-9_-]+)$/.exec(text);
    if (!match) continue;
    const [, set, indexRaw, totalRaw, data] = match;
    const index = Number(indexRaw), total = Number(totalRaw);
    if (index < 1 || total < 1 || total > 50 || index > total) continue;
    if (!sets.has(set)) sets.set(set, { total, parts: new Map() });
    const group = sets.get(set);
    if (group.total !== total) continue;
    group.parts.set(index, data);
  }
  const envelopes = [];
  for (const [set, group] of sets) {
    if (group.parts.size !== group.total) continue;
    try {
      const encoded = Array.from({ length: group.total }, (_, index) => group.parts.get(index + 1)).join('');
      envelopes.push({ set, envelope: JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) });
    } catch { /* 忽略损坏或被污染的分片 */ }
  }
  return envelopes;
}

function assembleShardedTxt(values) {
  const sets = new Map();
  for (const raw of values || []) {
    const text = parseTxtValue(raw);
    const match = /^r2;set=([^;]+);role=([AB]);part=(\d+)\/(\d+);data=([A-Za-z0-9_-]+)$/.exec(text);
    if (!match) continue;
    const [, set, role, indexRaw, totalRaw, data] = match;
    const index = Number(indexRaw), total = Number(totalRaw);
    if (index < 1 || total < 1 || total > 50 || index > total) continue;
    const key = `${set}:${role}`;
    if (!sets.has(key)) sets.set(key, { set, role, total, parts: new Map() });
    const group = sets.get(key);
    if (group.total === total) group.parts.set(index, data);
  }
  return [...sets.values()].filter(group => group.parts.size === group.total).map(group => ({
    set: group.set,
    role: group.role,
    bytes: Buffer.from(Array.from({ length: group.total }, (_, index) => group.parts.get(index + 1)).join(''), 'base64url')
  }));
}

function combineShards(shares) {
  const bySet = new Map();
  for (const share of shares || []) {
    if (!bySet.has(share.set)) bySet.set(share.set, {});
    bySet.get(share.set)[share.role] = share.bytes;
  }
  const envelopes = [];
  for (const [set, pair] of bySet) {
    if (!pair.A || !pair.B || pair.A.length !== pair.B.length) continue;
    try {
      const manifest = Buffer.alloc(pair.A.length);
      for (let index = 0; index < manifest.length; index += 1) manifest[index] = pair.A[index] ^ pair.B[index];
      const envelope = JSON.parse(manifest.toString('utf8'));
      const { signature, manifestHash, ...core } = envelope;
      const actual = crypto.createHash('sha256').update(stableStringify(core)).digest('hex');
      if (!signature || actual !== manifestHash) continue;
      envelopes.push({ set, envelope });
    } catch { /* ignore polluted shares */ }
  }
  return envelopes;
}

function dnsWireQuery(recordName) {
  const labels = recordName.split('.');
  const question = Buffer.concat([
    ...labels.map(label => Buffer.concat([Buffer.from([Buffer.byteLength(label)]), Buffer.from(label)])),
    Buffer.from([0, 0, 16, 0, 1])
  ]);
  return Buffer.concat([Buffer.from([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), question]);
}

function skipDnsName(buffer, offset) {
  let cursor = offset;
  while (cursor < buffer.length) {
    const length = buffer[cursor];
    if ((length & 0xc0) === 0xc0) return cursor + 2;
    cursor += 1;
    if (length === 0) return cursor;
    cursor += length;
  }
  throw new Error('DNS 响应名称越界');
}

function parseDnsWireTxt(input) {
  const buffer = Buffer.from(input);
  if (buffer.length < 12) throw new Error('DNS 响应过短');
  const questions = buffer.readUInt16BE(4), answers = buffer.readUInt16BE(6);
  let offset = 12;
  for (let index = 0; index < questions; index += 1) offset = skipDnsName(buffer, offset) + 4;
  const values = [];
  for (let index = 0; index < answers; index += 1) {
    offset = skipDnsName(buffer, offset);
    if (offset + 10 > buffer.length) throw new Error('DNS 响应记录越界');
    const type = buffer.readUInt16BE(offset), length = buffer.readUInt16BE(offset + 8);
    offset += 10;
    const end = offset + length;
    if (end > buffer.length) throw new Error('DNS TXT 数据越界');
    if (type === 16) {
      let cursor = offset, value = '';
      while (cursor < end) { const size = buffer[cursor]; cursor += 1; value += buffer.subarray(cursor, cursor + size).toString('utf8'); cursor += size; }
      values.push(value);
    }
    offset = end;
  }
  return values;
}

async function queryDoh(resolver, recordName, timeoutMs = 4000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const url = new URL(resolver.endpoint || resolver.url);
    const wire = dnsWireQuery(recordName);
    url.searchParams.set('dns', wire.toString('base64url'));
    const response = await fetch(url, { headers: { Accept: 'application/dns-message' }, signal: controller.signal, cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const values = parseDnsWireTxt(await response.arrayBuffer());
    return { id: resolver.id, label: resolver.label, ok: true, values, shares: assembleShardedTxt(values), envelopes: assembleTxt(values) };
  } catch (error) {
    return { id: resolver.id, label: resolver.label, ok: false, error: error.name === 'AbortError' ? '查询超时' : String(error.message || '查询失败'), values: [], shares: [], envelopes: [] };
  } finally { clearTimeout(timer); }
}

async function diagnoseDoh(recordName, profileId = 1, bootstrapId = null) {
  const settings = await RecoveryModel.getSettings(profileId);
  const publicKeys = [
    { keyId: settings.public_key_id, publicKey: settings.public_key },
    { keyId: settings.next_public_key_id, publicKey: settings.next_public_key }
  ].filter(item => item.keyId && item.publicKey);
  const routes = await RecoveryModel.listLookupRoutes(profileId, { enabledOnly: true });
  const selected = routes.filter(item => !bootstrapId || Number(item.bootstrap_id) === Number(bootstrapId));
  const results = await Promise.all(selected.map(route => queryDoh({
    id: route.resolver_id, label: route.resolver_label, endpoint: route.endpoint
  }, recordName, route.timeout_ms)));
  return results.map(result => ({
    ...result,
    shares: (result.shares || []).map(item => ({ set: item.set, role: item.role, bytes: item.bytes.length })),
    envelopes: result.envelopes.map(item => ({
      set: item.set,
      generation: Number(item.envelope?.generation || 0),
      keyId: item.envelope?.keyId || '',
      signatureValid: verifyEnvelope(item.envelope, publicKeys),
      envelope: item.envelope
    }))
  }));
}

function cloudflareCredential() {
  const own = RecoveryCredentialStore.cloudflareConfig();
  const source = own.reuseCentral ? IntegrationCredentialStore.cloudflareApiEdgeConfig() : own;
  if (!/^[a-f0-9]{32}$/i.test(source.accountId || '') || String(source.apiToken || '').length < 20) {
    throw new Error('恢复系统 Cloudflare DNS 凭据尚未配置');
  }
  return source;
}

function credentialConfigured(providerId, credentials = {}) {
  if (providerId === 'cloudflare') return /^[a-f0-9]{32}$/i.test(credentials.accountId || '') && String(credentials.apiToken || '').length >= 20;
  if (providerId === 'desec') return String(credentials.apiToken || '').length >= 20;
  if (providerId === 'cloudns') return ['auth-id', 'sub-auth-id', 'sub-auth-user'].includes(credentials.authType)
    && Boolean(String(credentials.authId || '').trim()) && String(credentials.authPassword || '').length >= 4;
  if (providerId === 'route53') return String(credentials.accessKeyId || '').length >= 16 && String(credentials.secretAccessKey || '').length >= 32;
  if (providerId === 'dnspod') return String(credentials.secretId || '').length >= 16 && String(credentials.secretKey || '').length >= 16;
  if (providerId === 'aliyun') return String(credentials.accessKeyId || '').length >= 12 && String(credentials.accessKeySecret || '').length >= 16;
  if (providerId === 'baidu') return String(credentials.accessKeyId || '').length >= 12 && String(credentials.secretAccessKey || '').length >= 16;
  if (providerId === 'volcengine') return String(credentials.accessKeyId || '').length >= 12 && String(credentials.secretAccessKey || '').length >= 16;
  return false;
}

function credentialsForChannel(channel) {
  if (!channel) return {};
  if (String(channel.credential_key || '').startsWith('legacy-cloudflare:')) {
    try { return cloudflareCredential(); } catch { return {}; }
  }
  const stored = RecoveryCredentialStore.dnsChannel(channel.credential_key);
  const credentials = stored.credentials || {};
  if (channel.provider_id === 'cloudflare' && credentials.reuseCentral === true) {
    return IntegrationCredentialStore.cloudflareApiEdgeConfig();
  }
  return credentials;
}

function normalizeChannelCredentials(providerId, input = {}, previous = {}) {
  const keep = (name, aliases = []) => {
    const value = [name, ...aliases].map(key => input[key]).find(item => String(item || '').trim());
    return String(value || previous[name] || '').trim();
  };
  if (providerId === 'cloudflare') {
    const reuseCentral = ['1', 1, true, 'true', 'on'].includes(input.reuseCentral);
    const credentials = { reuseCentral, accountId: keep('accountId'), apiToken: keep('apiToken') };
    const effective = reuseCentral ? IntegrationCredentialStore.cloudflareApiEdgeConfig() : credentials;
    if (!credentialConfigured(providerId, effective)) throw new Error(reuseCentral ? '中央 Cloudflare 凭据尚未配置完整' : 'Cloudflare Account ID 或 API Token 格式不正确');
    return credentials;
  }
  if (providerId === 'desec') {
    const credentials = { apiToken: keep('apiToken') };
    if (!credentialConfigured(providerId, credentials)) throw new Error('deSEC API Token 格式不正确');
    return credentials;
  }
  if (providerId === 'cloudns') {
    const credentials = {
      authType: String(input.authType || previous.authType || 'auth-id').trim(),
      authId: keep('authId'),
      authPassword: keep('authPassword')
    };
    if (!credentialConfigured(providerId, credentials)) throw new Error('ClouDNS 认证类型、账号或密码格式不正确');
    return credentials;
  }
  if (providerId === 'route53') {
    const credentials = {
      accessKeyId: keep('accessKeyId'),
      secretAccessKey: keep('secretAccessKey'),
      sessionToken: keep('sessionToken')
    };
    if (!credentialConfigured(providerId, credentials)) throw new Error('AWS Access Key ID 或 Secret Access Key 格式不正确');
    return credentials;
  }
  if (providerId === 'dnspod') {
    const credentials = { secretId: keep('secretId'), secretKey: keep('secretKey') };
    if (!credentialConfigured(providerId, credentials)) throw new Error('腾讯云 SecretId 或 SecretKey 格式不正确');
    return credentials;
  }
  if (providerId === 'aliyun') {
    const credentials = { accessKeyId: keep('accessKeyId'), accessKeySecret: keep('accessKeySecret') };
    if (!credentialConfigured(providerId, credentials)) throw new Error('阿里云 AccessKey ID 或 AccessKey Secret 格式不正确');
    return credentials;
  }
  if (providerId === 'baidu') {
    const credentials = { accessKeyId: keep('accessKeyId'), secretAccessKey: keep('secretAccessKey') };
    if (!credentialConfigured(providerId, credentials)) throw new Error('百度智能云 Access Key ID 或 Secret Access Key 格式不正确');
    return credentials;
  }
  if (providerId === 'volcengine') {
    const credentials = {
      accessKeyId: keep('accessKeyId'), secretAccessKey: keep('secretAccessKey'),
      sessionToken: keep('sessionToken'), region: keep('region') || 'cn-beijing'
    };
    if (!credentialConfigured(providerId, credentials)) throw new Error('火山引擎 Access Key ID 或 Secret Access Key 格式不正确');
    return credentials;
  }
  throw new Error('该 DNS 服务商当前不支持 API 自动发布');
}

function channelAccountHint(providerId, credentials) {
  const mask = value => {
    const text = String(value || '');
    if (text.length <= 8) return text ? `${text.slice(0, 2)}***` : '';
    return `${text.slice(0, 4)}…${text.slice(-4)}`;
  };
  if (providerId === 'cloudflare') return credentials.reuseCentral ? '复用中央凭据' : mask(credentials.accountId);
  if (providerId === 'desec') return mask(credentials.apiToken);
  if (providerId === 'cloudns') return `${credentials.authType}:${mask(credentials.authId)}`;
  if (providerId === 'route53') return mask(credentials.accessKeyId);
  if (providerId === 'dnspod') return mask(credentials.secretId);
  if (providerId === 'aliyun' || providerId === 'baidu' || providerId === 'volcengine') return mask(credentials.accessKeyId);
  return '';
}

function serializeDnsChannel(channel) {
  const credentials = credentialsForChannel(channel);
  const legacy = String(channel.credential_key || '').startsWith('legacy-cloudflare:');
  const stored = legacy ? RecoveryCredentialStore.cloudflareConfig() : RecoveryCredentialStore.dnsChannel(channel.credential_key).credentials;
  return {
    ...channel,
    configured: credentialConfigured(channel.provider_id, credentials),
    reuse_central: channel.provider_id === 'cloudflare' && stored.reuseCentral === true,
    auth_type: channel.provider_id === 'cloudns' ? String(stored.authType || 'auth-id') : undefined,
    region: channel.provider_id === 'volcengine' ? String(stored.region || 'cn-beijing') : undefined,
    legacy,
    credential_key: undefined
  };
}

async function ensureLegacyCloudflareChannel(profileId = 1) {
  const channels = await RecoveryModel.listDnsChannels(profileId);
  const existing = channels.find(item => item.credential_key === `legacy-cloudflare:${profileId}`);
  if (existing) {
    await RecoveryModel.assignDnsChannelToLegacyCloudflare(existing.id, profileId);
    return existing;
  }
  const records = await RecoveryModel.listBootstrapRecords({ profileId });
  const hasLegacyRecord = records.some(item => item.provider_id === 'cloudflare' && item.publish_mode === 'automatic' && !item.dns_channel_id);
  const credential = (() => { try { return cloudflareCredential(); } catch { return {}; } })();
  if (!hasLegacyRecord && !credentialConfigured('cloudflare', credential)) return null;
  const channel = await RecoveryModel.createDnsChannel({
    providerId: 'cloudflare', label: '默认 Cloudflare 通道',
    credentialKey: `legacy-cloudflare:${profileId}`,
    accountHint: channelAccountHint('cloudflare', credential), status: 1
  }, profileId);
  await RecoveryModel.assignDnsChannelToLegacyCloudflare(channel.id, profileId);
  return channel;
}

function validateChannelLabel(value) {
  const label = String(value || '').trim();
  if (!label || label.length > 80) throw new Error('API 通道名称需为 1 到 80 个字符');
  return label;
}

async function createDnsChannel(input = {}, profileId = 1) {
  const providerId = String(input.providerId || '').trim().toLowerCase();
  const capability = DnsPublisherService.providerCapabilities().find(item => item.id === providerId);
  if (!capability?.automaticPublish) throw new Error('该 DNS 服务商当前不支持 API 自动发布');
  const credentials = normalizeChannelCredentials(providerId, input);
  const credentialKey = `dns-${crypto.randomBytes(12).toString('hex')}`;
  await RecoveryCredentialStore.saveDnsChannel(credentialKey, providerId, credentials);
  try {
    const channel = await RecoveryModel.createDnsChannel({
      providerId, label: validateChannelLabel(input.label), credentialKey,
      accountHint: channelAccountHint(providerId, credentials),
      status: ['0', 0, false, 'false'].includes(input.status) ? 0 : 1
    }, profileId);
    await RecoveryModel.addAudit('dns-channel.create', { id: channel.id, providerId, label: channel.label }, true, '', profileId);
    return serializeDnsChannel(channel);
  } catch (error) {
    await RecoveryCredentialStore.deleteDnsChannel(credentialKey).catch(() => undefined);
    throw error;
  }
}

async function updateDnsChannel(id, input = {}, profileId = 1) {
  const current = await RecoveryModel.getDnsChannel(id, profileId);
  if (!current) throw new Error('DNS API 通道不存在');
  const providerId = String(input.providerId || current.provider_id).trim().toLowerCase();
  const capability = DnsPublisherService.providerCapabilities().find(item => item.id === providerId);
  if (!capability?.automaticPublish) throw new Error('该 DNS 服务商当前不支持 API 自动发布');
  const isLegacy = String(current.credential_key).startsWith('legacy-cloudflare:');
  const stored = RecoveryCredentialStore.dnsChannel(current.credential_key);
  const previous = providerId === current.provider_id ? (isLegacy ? credentialsForChannel(current) : stored.credentials) : {};
  const credentials = normalizeChannelCredentials(providerId, input, previous);
  if (isLegacy) {
    if (providerId !== 'cloudflare') throw new Error('默认兼容通道不能更换服务商，请新建 API 通道');
    await RecoveryCredentialStore.saveCloudflareConfig(credentials);
  } else {
    await RecoveryCredentialStore.saveDnsChannel(current.credential_key, providerId, credentials);
  }
  const channel = await RecoveryModel.updateDnsChannel(id, {
    providerId, label: validateChannelLabel(input.label),
    accountHint: channelAccountHint(providerId, credentials),
    status: ['0', 0, false, 'false'].includes(input.status) ? 0 : 1
  }, profileId);
  await RecoveryModel.addAudit('dns-channel.update', { id, providerId, label: channel.label }, true, '', profileId);
  return serializeDnsChannel(channel);
}

async function testDnsChannel(id, profileId = 1) {
  const channel = await RecoveryModel.getDnsChannel(id, profileId);
  if (!channel) throw new Error('DNS API 通道不存在');
  try {
    const result = await DnsPublisherService.verifyChannel(channel.provider_id, credentialsForChannel(channel));
    const updated = await RecoveryModel.saveDnsChannelTestResult(id, { ok: true });
    await RecoveryModel.addAudit('dns-channel.test', { id, providerId: channel.provider_id, zoneCount: result.zoneCount }, true, '', profileId);
    return { channel: serializeDnsChannel(updated), zoneCount: result.zoneCount, zones: result.zones };
  } catch (error) {
    await RecoveryModel.saveDnsChannelTestResult(id, { ok: false, error: error.message });
    await RecoveryModel.addAudit('dns-channel.test', { id, providerId: channel.provider_id }, false, error.message, profileId);
    throw error;
  }
}

async function listDnsChannelZones(id, profileId = 1) {
  const channel = await RecoveryModel.getDnsChannel(id, profileId);
  if (!channel) throw new Error('DNS API 通道不存在');
  return DnsPublisherService.listZones(channel.provider_id, credentialsForChannel(channel));
}

async function deleteDnsChannel(id, profileId = 1) {
  const channel = await RecoveryModel.getDnsChannel(id, profileId);
  if (!channel) throw new Error('DNS API 通道不存在');
  const references = await RecoveryModel.countDnsChannelReferences(id);
  if (Number(references?.count || 0) > 0) throw new Error('该 API 通道仍被 Bootstrap DNS 使用，请先迁移或改为手动发布');
  await RecoveryModel.deleteDnsChannel(id, profileId);
  if (!String(channel.credential_key).startsWith('legacy-cloudflare:')) await RecoveryCredentialStore.deleteDnsChannel(channel.credential_key);
  await RecoveryModel.addAudit('dns-channel.delete', { id, providerId: channel.provider_id, label: channel.label }, true, '', profileId);
}

async function publishRecord(record, release, profileId = 1, releaseShards = null) {
  const envelope = envelopeForRelease(release);
  const byteLimit = Math.min(PORTABLE_TXT_BYTES, Number(record.portable_record_bytes) || PORTABLE_TXT_BYTES);
  const sharded = releaseShards || shardEnvelope(envelope, byteLimit);
  const role = String(record.share_role || 'LEGACY').toUpperCase();
  const chunked = role === 'LEGACY' ? chunkEnvelope(envelope) : sharded[role];
  if (!chunked) throw new Error('Bootstrap TXT 分片角色不正确');
  assertPortableTxt(chunked.parts, byteLimit);
  if (String(record.publish_mode || '').toLowerCase() === 'manual') {
    const diagnosis = await diagnoseDoh(record.record_name, profileId, record.id);
    const verified = role === 'LEGACY'
      ? diagnosis.some(result => result.envelopes.some(item => item.generation === release.generation && item.signatureValid))
      : diagnosis.some(result => result.shares?.some(item => item.set === chunked.set && item.role === role));
    if (verified) {
      await RecoveryModel.saveBootstrapPublishResult(record.id, { status: 'verified', generation: release.generation, verified: true });
      return { recordId: record.id, recordName: record.record_name, providerId: record.provider_id, role, verified: true, chunks: chunked.parts.length, byteLimit, diagnosis };
    }
    await RecoveryModel.saveBootstrapPublishResult(record.id, { status: 'manual_required', error: '请在对应权威 DNS 控制台写入以下 TXT，再执行 DoH 回读验证' });
    return { recordId: record.id, recordName: record.record_name, providerId: record.provider_id, role, verified: false, manualRequired: true, byteLimit, values: chunked.parts, diagnosis };
  }
  const channel = await RecoveryModel.getDnsChannel(record.dns_channel_id, profileId);
  if (!channel || Number(channel.status) !== 1) throw new Error(`${record.label} 尚未绑定已启用的 DNS API 通道`);
  if (channel.provider_id !== record.provider_id) throw new Error(`${record.label} 绑定的 API 通道与 DNS 服务商不匹配`);
  const operation = await DnsPublisherService.createPublishOperation(record.provider_id, credentialsForChannel(channel), {
    zoneName: record.zone_name,
    providerZoneId: record.provider_zone_id,
    recordName: record.record_name,
    values: chunked.parts,
    generation: release.generation
  });
  try {
    let diagnosis = [];
    let verified = false;
    for (let attempt = 0; attempt < 3 && !verified; attempt += 1) {
      if (attempt) await new Promise(resolve => setTimeout(resolve, 1500));
      diagnosis = await diagnoseDoh(record.record_name, profileId, record.id);
      verified = diagnosis.some(result => role === 'LEGACY'
        ? result.envelopes.some(item => item.generation === release.generation && item.signatureValid)
        : result.shares?.some(item => item.set === chunked.set && item.role === role));
    }
    if (!verified) throw new Error('新 TXT 已写入，但多 DoH 回读尚未发现有效的新版本');
    await operation.commit();
    await RecoveryModel.saveBootstrapPublishResult(record.id, { status: 'verified', generation: release.generation, verified: true });
    return { recordId: record.id, recordName: record.record_name, providerId: record.provider_id, channelId: channel.id, role, verified: true, chunks: chunked.parts.length, byteLimit, diagnosis };
  } catch (error) {
    await operation.rollback().catch(() => undefined);
    await RecoveryModel.saveBootstrapPublishResult(record.id, { status: 'failed', error: error.message });
    throw error;
  }
}

async function publishRelease(id, profileId = null) {
  const release = await RecoveryModel.getRelease(id, profileId);
  if (!release) throw new Error('恢复版本不存在');
  profileId = Number(release.profile_id || profileId || 1);
  if (!['draft', 'failed'].includes(release.status)) throw new Error('该版本当前不可发布');
  const settings = await RecoveryModel.getSettings(profileId);
  const publicKeys = [
    { keyId: settings.public_key_id, publicKey: settings.public_key },
    { keyId: settings.next_public_key_id, publicKey: settings.next_public_key }
  ].filter(item => item.keyId && item.publicKey);
  const envelope = envelopeForRelease(release);
  if (!verifyEnvelope(envelope, publicKeys)) throw new Error('恢复版本签名校验失败，拒绝发布');
  await ensureLegacyCloudflareChannel(profileId);
  const records = await RecoveryModel.listBootstrapRecords({ enabledOnly: true, profileId });
  const signing = RecoveryCredentialStore.signingKeys(profileId);
  const releaseSecret = signing.current?.keyId === release.key_id ? signing.current.privateKey : '';
  if (records.some(item => ['A', 'B'].includes(String(item.share_role || '').toUpperCase())) && !releaseSecret) {
    throw new Error('无法读取该版本对应的签名私钥，不能生成稳定的 A/B 分片');
  }
  const releaseShards = releaseSecret ? shardEnvelope(envelope, PORTABLE_TXT_BYTES, releaseSecret) : null;
  const results = [];
  try {
    for (const record of records) results.push(await publishRecord(record, release, profileId, releaseShards));
    const shardedRecords = records.filter(item => ['A', 'B'].includes(String(item.share_role || '').toUpperCase()));
    if (shardedRecords.length) {
      const verifiedA = results.filter(item => item.verified && item.role === 'A');
      const verifiedB = results.filter(item => item.verified && item.role === 'B');
      const crossProvider = verifiedA.some(a => verifiedB.some(b => a.providerId !== b.providerId));
      if (!verifiedA.length || !verifiedB.length || !crossProvider) {
        await RecoveryModel.markRelease(id, 'failed', { error: 'A/B 分片尚未形成跨权威 DNS 的可恢复组合' });
        return {
          published: false,
          release: serializeRelease(await RecoveryModel.getRelease(id)),
          dnsPublished: results.filter(item => item.verified).length,
          records: results,
          manualRecords: results.filter(item => item.manualRequired),
          warning: '尚未满足发布门槛：至少需要一个已验证 A 分片和一个来自不同权威 DNS 托管商的已验证 B 分片。手动记录写入后请重新发布。'
        };
      }
    }
    await RecoveryModel.publishReleaseAtomically(release.id, release.generation, profileId);
    await RecoveryModel.addAudit('release.publish', { id, generation: release.generation, dnsRecords: results.length }, true, '', profileId);
    return { published: true, release: serializeRelease(await RecoveryModel.getRelease(id)), dnsPublished: results.filter(item => item.verified).length, records: results, warning: records.length ? '' : '尚未配置 Bootstrap DNS；当前版本只会通过主站同步给已访问用户。' };
  } catch (error) {
    await RecoveryModel.markRelease(id, 'failed', { error: error.message });
    await RecoveryModel.addAudit('release.publish', { id, generation: release.generation }, false, error.message, profileId);
    throw error;
  }
}

async function rollbackTo(sourceId, profileId = null) {
  const source = await RecoveryModel.getRelease(sourceId, profileId);
  if (!source) throw new Error('要回滚的历史版本不存在');
  profileId = Number(source.profile_id || profileId || 1);
  const settings = await RecoveryModel.getSettings(profileId);
  const key = await ensureCurrentKey(profileId);
  const generation = await RecoveryModel.nextGeneration(profileId);
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + Number(settings.manifest_valid_days) * 86400;
  const payloadCore = {
    ...JSON.parse(source.payload_json), generation, issuedAt, expiresAt, keyId: key.keyId,
    trustedKeys: [
      { keyId: settings.public_key_id || key.keyId, spki: publicKeyPemToSpkiBase64(settings.public_key || key.publicKey) },
      { keyId: settings.next_public_key_id, spki: publicKeyPemToSpkiBase64(settings.next_public_key) }
    ].filter(item => item.keyId && item.spki)
  };
  delete payloadCore.manifestHash;
  const payload = Number(payloadCore.schema) >= 3
    ? { ...payloadCore, manifestHash: crypto.createHash('sha256').update(stableStringify(payloadCore)).digest('hex') }
    : payloadCore;
  const payloadJson = stableStringify(payload);
  const release = await RecoveryModel.createRelease({
    generation,
    payloadJson,
    payloadHash: crypto.createHash('sha256').update(payloadJson).digest('hex'),
    signature: signPayload(payload, key.privateKey),
    keyId: key.keyId,
    status: 'draft',
    issuedAt: new Date(issuedAt * 1000).toISOString(),
    expiresAt: new Date(expiresAt * 1000).toISOString(),
    sourceReleaseId: source.id
  }, profileId);
  await RecoveryModel.addAudit('release.rollback.draft', { sourceId, id: release.id, generation }, true, '', profileId);
  return publishRelease(release.id, profileId);
}

async function profileForFrontend(frontendOrigin) {
  if (!frontendOrigin) return RecoveryModel.getProfile(1);
  let hostname;
  try { hostname = new URL(frontendOrigin).hostname.toLowerCase(); }
  catch { return null; }
  const worker = await CloudflareFrontendModel.getWorkerByHostname(hostname);
  if (!worker?.recovery_profile_id) return null;
  return RecoveryModel.getProfile(worker.recovery_profile_id);
}

async function getPublicManifest(frontendOrigin = '') {
  const profile = await profileForFrontend(frontendOrigin);
  if (!profile) return { enabled: false, componentVersion: 'recovery-v2', reason: 'frontend_unbound' };
  const profileId = profile.id;
  const [settings, release, bootstraps] = await Promise.all([
    RecoveryModel.getSettings(profileId),
    RecoveryModel.getLatestPublishedRelease(profileId),
    RecoveryModel.listLookupRoutes(profileId, { enabledOnly: true })
  ]);
  if (Number(settings.enabled) !== 1 || !release) return { enabled: false, componentVersion: settings.component_version };
  const envelope = envelopeForRelease(release);
  return {
    enabled: true,
    componentVersion: settings.component_version,
    envelope,
    publicKeys: [...(Array.isArray(envelope.trustedKeys) ? envelope.trustedKeys : []),
      { keyId: settings.public_key_id, spki: publicKeyPemToSpkiBase64(settings.public_key) },
      { keyId: settings.next_public_key_id, spki: publicKeyPemToSpkiBase64(settings.next_public_key) }
    ].filter((item, index, items) => item.keyId && item.spki && items.findIndex(candidate => candidate.keyId === item.keyId) === index),
    localFallback: {
      email: settings.recovery_email || '',
      publishUrl: settings.recovery_publish_url || '',
      contact: settings.recovery_contact || '',
      message: settings.recovery_message || '',
      foundMessage: settings.found_message || ''
    },
    bootstrapNames: [...new Set(bootstraps.map(item => item.record_name))],
    lookupRoutes: bootstraps.map(item => ({
      resolverId: item.resolver_id, resolverLabel: item.resolver_label,
      endpoint: item.endpoint, format: item.response_format,
      bootstrapName: item.record_name, priority: Number(item.priority_group),
      timeoutMs: Number(item.timeout_ms)
    }))
  };
}

async function overview(profileId = 1) {
  await ensureLegacyCloudflareChannel(profileId);
  const [profiles, settings, domains, bootstraps, routes, releases, keys, audit, frontendWorkers, resolvers, dnsProviders, dnsChannels] = await Promise.all([
    RecoveryModel.listProfiles(), RecoveryModel.getSettings(profileId), RecoveryModel.listDomains({ profileId }), RecoveryModel.listBootstrapRecords({ profileId }),
    RecoveryModel.listLookupRoutes(profileId), RecoveryModel.listReleases(50, profileId), keyStatus(profileId), RecoveryModel.listAudit(100, profileId), CloudflareFrontendModel.listWorkers(), RecoveryModel.listResolvers(), RecoveryModel.listDnsProviders(), RecoveryModel.listDnsChannels(profileId)
  ]);
  const previewWorker = frontendWorkers.find(worker =>
    Number(worker.recovery_profile_id) === Number(profileId)
      && worker.state === 'ready'
      && Boolean(worker.hostname)
      && !worker.retired_at
  );
  const credential = RecoveryCredentialStore.cloudflareConfig();
  const central = IntegrationCredentialStore.cloudflareApiEdgeConfig();
  return {
    profiles: profiles.map(item => ({ ...item, ready: Number(item.enabled) === 1 && Boolean(item.public_key_id) })),
    selectedProfileId: Number(settings?.id || profileId),
    settings,
    domains,
    bootstraps,
    releases: releases.map(serializeRelease),
    keys,
    cloudflare: {
      reuseCentral: credential.reuseCentral,
      configured: credential.reuseCentral
        ? Boolean(central.accountId && central.apiToken)
        : Boolean(credential.accountId && credential.apiToken),
      accountId: credential.reuseCentral ? (central.accountId || '') : (credential.accountId || ''),
      tokenConfigured: credential.reuseCentral ? Boolean(central.apiToken) : Boolean(credential.apiToken)
    },
    resolvers,
    dnsProviders: dnsProviders.map(provider => ({
      ...provider,
      automatic_publish: DnsPublisherService.providerCapabilities().find(item => item.id === provider.id)?.automaticPublish === true
    })),
    dnsChannels: dnsChannels.map(serializeDnsChannel),
    lookupRoutes: routes,
    publicPreviewOrigin: previewWorker ? `https://${previewWorker.hostname}` : '',
    audit
  };
}

async function saveCloudflareCredentials(input = {}, profileId = 1) {
  const reuseCentral = ['1', 1, true, 'true', 'on'].includes(input.reuseCentral);
  const current = RecoveryCredentialStore.cloudflareConfig();
  const accountId = String(input.accountId || current.accountId || '').trim();
  const apiToken = String(input.apiToken || current.apiToken || '').trim();
  if (!reuseCentral) {
    if (!/^[a-f0-9]{32}$/i.test(accountId)) throw new Error('Cloudflare Account ID 格式不正确');
    if (apiToken.length < 20) throw new Error('Cloudflare API Token 格式不正确');
  }
  await RecoveryCredentialStore.saveCloudflareConfig({ reuseCentral, accountId, apiToken });
  await RecoveryModel.addAudit('credential.cloudflare.update', { reuseCentral, accountId }, true, '', profileId);
  return overview(profileId);
}

function validateLookupRouteInput(input = {}) {
  const resolverId = String(input.resolverId || '').trim();
  const bootstrapId = Number.parseInt(input.bootstrapId, 10);
  if (!resolverId) throw new Error('请选择 DNS 服务商');
  if (!Number.isInteger(bootstrapId) || bootstrapId < 1) throw new Error('请选择 Bootstrap TXT');
  return {
    resolverId, bootstrapId,
    priorityGroup: Math.max(1, Math.min(4, Number.parseInt(input.priorityGroup, 10) || 1)),
    timeoutMs: Math.max(800, Math.min(10000, Number.parseInt(input.timeoutMs, 10) || 2500)),
    sortOrder: Math.max(-100000, Math.min(100000, Number.parseInt(input.sortOrder, 10) || 0)),
    status: ['1', 1, true, 'true', 'on'].includes(input.status) ? 1 : 0
  };
}

async function assertProfileReady(profileId) {
  const [profile, domains] = await Promise.all([
    RecoveryModel.getProfile(profileId), RecoveryModel.listDomains({ enabledOnly: true, profileId })
  ]);
  if (!profile || profile.status !== 'active') throw new Error('所选恢复方案不存在或已停用');
  if (Number(profile.enabled) !== 1) throw new Error('所选恢复方案尚未启用');
  if (!domains.length) throw new Error('所选恢复方案没有启用的备用域名');
  if (!await RecoveryModel.getLatestPublishedRelease(profileId)) throw new Error('所选恢复方案尚未发布正式版本');
  return profile;
}

module.exports = {
  HEALTH_PATH,
  DOH_RESOLVERS,
  stableStringify,
  normalizeOrigin,
  validateDomainInput,
  validateBootstrapInput,
  validateBootstrapConfiguration,
  validateLookupRouteInput,
  updateSettings,
  ensureCurrentKey,
  generateNextKey,
  promoteNextKey,
  keyStatus,
  probeDomain,
  probeAndSave,
  probeAll,
  createDraft,
  publishRelease,
  rollbackTo,
  getPublicManifest,
  overview,
  diagnoseDoh,
  saveCloudflareCredentials,
  createDnsChannel,
  updateDnsChannel,
  testDnsChannel,
  listDnsChannelZones,
  deleteDnsChannel,
  verifyEnvelope,
  chunkEnvelope,
  assembleTxt,
  shardEnvelope,
  assembleShardedTxt,
  combineShards,
  assertPortableTxt,
  assertProfileReady
};
