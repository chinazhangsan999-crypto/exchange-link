'use strict';

const crypto = require('crypto');
const axios = require('axios');
const RecoveryModel = require('../models/RecoveryModel');
const FrontendOriginModel = require('../models/FrontendOriginModel');
const CloudflareFrontendModel = require('../models/CloudflareFrontendModel');
const RecoveryCredentialStore = require('./RecoveryCredentialStore');
const IntegrationCredentialStore = require('./IntegrationCredentialStore');
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
  return {
    label,
    zoneName,
    recordName,
    isPrimary: ['1', 1, true, 'true', 'on'].includes(input.isPrimary) ? 1 : 0,
    status: ['1', 1, true, 'true', 'on'].includes(input.status) ? 1 : 0,
    sortOrder: Math.max(-100000, Math.min(100000, Number.parseInt(input.sortOrder, 10) || 0))
  };
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
  const [settings, domains, bootstraps] = await Promise.all([
    RecoveryModel.getSettings(profileId),
    RecoveryModel.listDomains({ enabledOnly: true, profileId }),
    RecoveryModel.listLookupRoutes(profileId, { enabledOnly: true })
  ]);
  if (!domains.length) throw new Error('至少需要一条已启用的恢复线路');
  if (domains.length > settings.max_domains) throw new Error(`已启用线路超过后台限制（最多 ${settings.max_domains} 条）`);
  const key = await ensureCurrentKey(profileId);
  const generation = await RecoveryModel.nextGeneration(profileId);
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + Number(settings.manifest_valid_days) * 86400;
  const payload = {
    schema: 2,
    project: settings.project_id,
    generation,
    issuedAt,
    expiresAt,
    domains: domains.map(item => ({ title: item.title, url: item.url, priority: Number(item.priority) })),
    fallback: {
      email: settings.recovery_email || '',
      publishUrl: settings.recovery_publish_url || '',
      contact: settings.recovery_contact || '',
      message: settings.recovery_message || ''
    },
    foundMessage: settings.found_message || '',
    lookupRoutes: bootstraps.map(item => ({
      resolverId: item.resolver_id,
      resolverLabel: item.resolver_label,
      endpoint: item.endpoint,
      format: item.response_format,
      bootstrapName: item.record_name,
      priority: Number(item.priority_group),
      timeoutMs: Number(item.timeout_ms)
    })),
    trustedKeys: [
      { keyId: settings.public_key_id || key.keyId, spki: publicKeyPemToSpkiBase64(settings.public_key || key.publicKey) },
      { keyId: settings.next_public_key_id, spki: publicKeyPemToSpkiBase64(settings.next_public_key) }
    ].filter(item => item.keyId && item.spki),
    keyId: key.keyId
  };
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
    return { id: resolver.id, label: resolver.label, ok: true, envelopes: assembleTxt(values) };
  } catch (error) {
    return { id: resolver.id, label: resolver.label, ok: false, error: error.name === 'AbortError' ? '查询超时' : String(error.message || '查询失败'), envelopes: [] };
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

async function cloudflareRequest(method, pathname, body) {
  const credential = cloudflareCredential();
  const response = await fetch(`https://api.cloudflare.com/client/v4${pathname}`, {
    method,
    headers: { Authorization: `Bearer ${credential.apiToken}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok || payload?.success !== true) throw new Error(payload?.errors?.[0]?.message || `Cloudflare API 返回 HTTP ${response.status}`);
  return payload.result;
}

async function resolveZoneId(zoneName) {
  const credential = cloudflareCredential();
  const zones = await cloudflareRequest('GET', `/zones?name=${encodeURIComponent(zoneName)}&status=active&account.id=${encodeURIComponent(credential.accountId)}`);
  const exact = zones.find(item => String(item.name).toLowerCase() === zoneName.toLowerCase());
  if (!exact?.id) throw new Error(`Cloudflare 未找到 Active Zone：${zoneName}`);
  return exact.id;
}

async function publishRecord(record, release, profileId = 1) {
  const envelope = envelopeForRelease(release);
  const chunked = chunkEnvelope(envelope);
  const zoneId = await resolveZoneId(record.zone_name);
  const existing = await cloudflareRequest('GET', `/zones/${zoneId}/dns_records?type=TXT&name=${encodeURIComponent(record.record_name)}&per_page=100`);
  const created = [];
  try {
    for (const content of chunked.parts) {
      created.push(await cloudflareRequest('POST', `/zones/${zoneId}/dns_records`, {
        type: 'TXT', name: record.record_name, content, ttl: 60, comment: `navigation recovery generation ${release.generation}`
      }));
    }
    let diagnosis = [];
    let verified = false;
    for (let attempt = 0; attempt < 3 && !verified; attempt += 1) {
      if (attempt) await new Promise(resolve => setTimeout(resolve, 1500));
      diagnosis = await diagnoseDoh(record.record_name, profileId, record.id);
      verified = diagnosis.some(result => result.envelopes.some(item => item.generation === release.generation && item.signatureValid));
    }
    if (!verified) throw new Error('新 TXT 已写入，但多 DoH 回读尚未发现有效的新版本');
    for (const old of existing) {
      if (String(old.content || '').includes(`set=${chunked.set};`)) continue;
      if (String(old.content || '').startsWith('r1;set=')) {
        await cloudflareRequest('DELETE', `/zones/${zoneId}/dns_records/${encodeURIComponent(old.id)}`);
      }
    }
    await RecoveryModel.saveBootstrapPublishResult(record.id, { status: 'verified', generation: release.generation, verified: true });
    return { recordId: record.id, recordName: record.record_name, verified: true, chunks: chunked.parts.length, diagnosis };
  } catch (error) {
    for (const item of created) {
      if (item?.id) await cloudflareRequest('DELETE', `/zones/${zoneId}/dns_records/${encodeURIComponent(item.id)}`).catch(() => undefined);
    }
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
  const records = await RecoveryModel.listBootstrapRecords({ enabledOnly: true, profileId });
  const results = [];
  try {
    for (const record of records.filter(item => Number(item.is_primary) === 0)) results.push(await publishRecord(record, release, profileId));
    for (const record of records.filter(item => Number(item.is_primary) === 1)) results.push(await publishRecord(record, release, profileId));
    await RecoveryModel.publishReleaseAtomically(release.id, release.generation, profileId);
    await RecoveryModel.addAudit('release.publish', { id, generation: release.generation, dnsRecords: results.length }, true, '', profileId);
    return { release: serializeRelease(await RecoveryModel.getRelease(id)), dnsPublished: results.length, records: results, warning: records.length ? '' : '尚未配置 Bootstrap DNS；当前版本只会通过主站同步给已访问用户。' };
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
  const payload = {
    ...JSON.parse(source.payload_json), generation, issuedAt, expiresAt, keyId: key.keyId,
    trustedKeys: [
      { keyId: settings.public_key_id || key.keyId, spki: publicKeyPemToSpkiBase64(settings.public_key || key.publicKey) },
      { keyId: settings.next_public_key_id, spki: publicKeyPemToSpkiBase64(settings.next_public_key) }
    ].filter(item => item.keyId && item.spki)
  };
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
    publicKeys: Array.isArray(envelope.trustedKeys) ? envelope.trustedKeys : [],
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
  const [profiles, settings, domains, bootstraps, routes, releases, keys, audit, frontendOrigins, resolvers] = await Promise.all([
    RecoveryModel.listProfiles(), RecoveryModel.getSettings(profileId), RecoveryModel.listDomains({ profileId }), RecoveryModel.listBootstrapRecords({ profileId }),
    RecoveryModel.listLookupRoutes(profileId), RecoveryModel.listReleases(50, profileId), keyStatus(profileId), RecoveryModel.listAudit(100, profileId), FrontendOriginModel.listEnabledOrigins(), RecoveryModel.listResolvers()
  ]);
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
    lookupRoutes: routes,
    publicPreviewOrigin: frontendOrigins[0]?.origin || '',
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
  verifyEnvelope,
  chunkEnvelope,
  assembleTxt
  ,assertProfileReady
};
