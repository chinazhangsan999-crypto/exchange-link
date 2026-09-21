'use strict';

const crypto = require('crypto');
const axios = require('axios');
const RecoveryModel = require('../models/RecoveryModel');
const FrontendOriginModel = require('../models/FrontendOriginModel');
const RecoveryCredentialStore = require('./RecoveryCredentialStore');
const IntegrationCredentialStore = require('./IntegrationCredentialStore');
const { assertSafeBacklinkUrl, createPinnedAxiosConfig } = require('./InspectionService');
const { runPromisePool } = require('../utils/asyncPool');

const HEALTH_PATH = '/.well-known/route-health.gif';
const GIF_1X1 = Buffer.from('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==', 'base64');
const DOH_RESOLVERS = Object.freeze([
  { id: 'dnspod', label: 'DNSPod', url: 'https://doh.pub/dns-query' },
  { id: 'alidns', label: 'AliDNS', url: 'https://dns.alidns.com/resolve' },
  { id: 'cloudflare', label: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { id: 'google', label: 'Google', url: 'https://dns.google/resolve' }
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

async function ensureCurrentKey() {
  const settings = await RecoveryModel.getSettings();
  const stored = RecoveryCredentialStore.signingKeys();
  if (settings.public_key_id && settings.public_key && stored.current?.privateKey) return stored.current;
  const generated = keyPair();
  await RecoveryCredentialStore.saveSigningKeys({ ...stored, current: generated });
  await RecoveryModel.saveKeyState({ public_key_id: generated.keyId, public_key: generated.publicKey });
  await RecoveryModel.addAudit('key.generate.current', { keyId: generated.keyId });
  return generated;
}

async function generateNextKey() {
  await ensureCurrentKey();
  const stored = RecoveryCredentialStore.signingKeys();
  const generated = keyPair();
  await RecoveryCredentialStore.saveSigningKeys({ current: stored.current, next: generated });
  await RecoveryModel.saveKeyState({ next_public_key_id: generated.keyId, next_public_key: generated.publicKey });
  await RecoveryModel.addAudit('key.generate.next', { keyId: generated.keyId });
  return keyStatus();
}

async function promoteNextKey() {
  const stored = RecoveryCredentialStore.signingKeys();
  if (!stored.next?.privateKey) throw new Error('尚未生成下一代密钥');
  const [settings, published] = await Promise.all([
    RecoveryModel.getSettings(),
    RecoveryModel.getLatestPublishedRelease()
  ]);
  if (!published) throw new Error('请先发布包含下一代公钥的过渡版本，再提升密钥');
  const envelope = envelopeForRelease(published);
  const currentKeys = [{ keyId: settings.public_key_id, publicKey: settings.public_key }];
  const nextIsTrusted = Array.isArray(envelope.trustedKeys)
    && envelope.trustedKeys.some(item => item.keyId === stored.next.keyId && item.spki);
  if (!verifyEnvelope(envelope, currentKeys) || !nextIsTrusted) {
    throw new Error('当前正式版本尚未安全发布下一代公钥，请先生成并发布过渡版本');
  }
  await RecoveryCredentialStore.saveSigningKeys({ current: stored.next, next: null });
  await RecoveryModel.saveKeyState({
    public_key_id: stored.next.keyId,
    public_key: stored.next.publicKey,
    next_public_key_id: '',
    next_public_key: ''
  });
  await RecoveryModel.addAudit('key.promote', { keyId: stored.next.keyId });
  return keyStatus();
}

async function keyStatus() {
  const settings = await RecoveryModel.getSettings();
  const stored = RecoveryCredentialStore.signingKeys();
  return {
    currentKeyId: settings.public_key_id || '',
    currentPublicKey: settings.public_key || '',
    currentPrivateKeyConfigured: Boolean(stored.current?.privateKey),
    nextKeyId: settings.next_public_key_id || '',
    nextPublicKey: settings.next_public_key || '',
    nextPrivateKeyConfigured: Boolean(stored.next?.privateKey)
  };
}

async function updateSettings(input = {}) {
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
  const saved = await RecoveryModel.updateSettings(normalized);
  await RecoveryModel.addAudit('settings.update', { enabled: saved.enabled });
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

async function probeAndSave(id) {
  const domain = await RecoveryModel.getDomain(id);
  if (!domain) throw new Error('恢复线路不存在');
  const settings = await RecoveryModel.getSettings();
  let result = await probeDomain(domain, { timeoutMs: settings.probe_timeout_ms });
  if (!result.healthy) result = await probeDomain(domain, { timeoutMs: settings.probe_timeout_ms });
  await RecoveryModel.saveProbeResult(id, result);
  await RecoveryModel.addAudit('domain.probe', { id, url: domain.url, healthy: result.healthy }, result.healthy, result.error);
  return { ...domain, ...result };
}

async function probeAll() {
  const settings = await RecoveryModel.getSettings();
  const domains = await RecoveryModel.listDomains({ enabledOnly: true });
  const settled = await runPromisePool(domains, settings.probe_concurrency, async domain => probeAndSave(domain.id), settings.probe_timeout_ms * 3);
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

async function createDraft({ sourceReleaseId = null } = {}) {
  const [settings, domains, bootstraps] = await Promise.all([
    RecoveryModel.getSettings(),
    RecoveryModel.listDomains({ enabledOnly: true }),
    RecoveryModel.listBootstrapRecords({ enabledOnly: true })
  ]);
  if (!domains.length) throw new Error('至少需要一条已启用的恢复线路');
  if (domains.length > settings.max_domains) throw new Error(`已启用线路超过后台限制（最多 ${settings.max_domains} 条）`);
  const key = await ensureCurrentKey();
  const generation = await RecoveryModel.nextGeneration();
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + Number(settings.manifest_valid_days) * 86400;
  const payload = {
    schema: 1,
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
    bootstrapNames: bootstraps.map(item => item.record_name),
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
  });
  await RecoveryModel.addAudit('release.draft', { id: release.id, generation });
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

async function queryDoh(resolver, recordName, timeoutMs = 4000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const url = new URL(resolver.url);
    url.searchParams.set('name', recordName);
    url.searchParams.set('type', 'TXT');
    const response = await fetch(url, { headers: { Accept: 'application/dns-json' }, signal: controller.signal, cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    const values = (Array.isArray(data.Answer) ? data.Answer : []).filter(item => Number(item.type) === 16).map(item => item.data);
    return { id: resolver.id, label: resolver.label, ok: true, envelopes: assembleTxt(values) };
  } catch (error) {
    return { id: resolver.id, label: resolver.label, ok: false, error: error.name === 'AbortError' ? '查询超时' : String(error.message || '查询失败'), envelopes: [] };
  } finally { clearTimeout(timer); }
}

async function diagnoseDoh(recordName) {
  const settings = await RecoveryModel.getSettings();
  const publicKeys = [
    { keyId: settings.public_key_id, publicKey: settings.public_key },
    { keyId: settings.next_public_key_id, publicKey: settings.next_public_key }
  ].filter(item => item.keyId && item.publicKey);
  const results = await Promise.all(DOH_RESOLVERS.map(resolver => queryDoh(resolver, recordName)));
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

async function publishRecord(record, release) {
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
      diagnosis = await diagnoseDoh(record.record_name);
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

async function publishRelease(id) {
  const release = await RecoveryModel.getRelease(id);
  if (!release) throw new Error('恢复版本不存在');
  if (!['draft', 'failed'].includes(release.status)) throw new Error('该版本当前不可发布');
  const settings = await RecoveryModel.getSettings();
  const publicKeys = [
    { keyId: settings.public_key_id, publicKey: settings.public_key },
    { keyId: settings.next_public_key_id, publicKey: settings.next_public_key }
  ].filter(item => item.keyId && item.publicKey);
  const envelope = envelopeForRelease(release);
  if (!verifyEnvelope(envelope, publicKeys)) throw new Error('恢复版本签名校验失败，拒绝发布');
  const records = await RecoveryModel.listBootstrapRecords({ enabledOnly: true });
  const results = [];
  try {
    for (const record of records.filter(item => Number(item.is_primary) === 0)) results.push(await publishRecord(record, release));
    for (const record of records.filter(item => Number(item.is_primary) === 1)) results.push(await publishRecord(record, release));
    await RecoveryModel.publishReleaseAtomically(release.id, release.generation);
    await RecoveryModel.addAudit('release.publish', { id, generation: release.generation, dnsRecords: results.length });
    return { release: serializeRelease(await RecoveryModel.getRelease(id)), dnsPublished: results.length, records: results, warning: records.length ? '' : '尚未配置 Bootstrap DNS；当前版本只会通过主站同步给已访问用户。' };
  } catch (error) {
    await RecoveryModel.markRelease(id, 'failed', { error: error.message });
    await RecoveryModel.addAudit('release.publish', { id, generation: release.generation }, false, error.message);
    throw error;
  }
}

async function rollbackTo(sourceId) {
  const source = await RecoveryModel.getRelease(sourceId);
  if (!source) throw new Error('要回滚的历史版本不存在');
  const settings = await RecoveryModel.getSettings();
  const key = await ensureCurrentKey();
  const generation = await RecoveryModel.nextGeneration();
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
  });
  await RecoveryModel.addAudit('release.rollback.draft', { sourceId, id: release.id, generation });
  return publishRelease(release.id);
}

async function getPublicManifest() {
  const [settings, release, bootstraps] = await Promise.all([
    RecoveryModel.getSettings(),
    RecoveryModel.getLatestPublishedRelease(),
    RecoveryModel.listBootstrapRecords({ enabledOnly: true })
  ]);
  if (Number(settings.enabled) !== 1 || !release) return { enabled: false, componentVersion: settings.component_version };
  const envelope = envelopeForRelease(release);
  return {
    enabled: true,
    componentVersion: settings.component_version,
    envelope,
    publicKeys: Array.isArray(envelope.trustedKeys) ? envelope.trustedKeys : [],
    bootstrapNames: bootstraps.map(item => item.record_name)
  };
}

async function overview() {
  const [settings, domains, bootstraps, releases, keys, audit, frontendOrigins] = await Promise.all([
    RecoveryModel.getSettings(), RecoveryModel.listDomains(), RecoveryModel.listBootstrapRecords(),
    RecoveryModel.listReleases(), keyStatus(), RecoveryModel.listAudit(100), FrontendOriginModel.listEnabledOrigins()
  ]);
  const credential = RecoveryCredentialStore.cloudflareConfig();
  const central = IntegrationCredentialStore.cloudflareApiEdgeConfig();
  return {
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
    resolvers: DOH_RESOLVERS.map(({ id, label }) => ({ id, label, enabled: true })),
    publicPreviewOrigin: frontendOrigins[0]?.origin || '',
    audit
  };
}

async function saveCloudflareCredentials(input = {}) {
  const reuseCentral = ['1', 1, true, 'true', 'on'].includes(input.reuseCentral);
  const current = RecoveryCredentialStore.cloudflareConfig();
  const accountId = String(input.accountId || current.accountId || '').trim();
  const apiToken = String(input.apiToken || current.apiToken || '').trim();
  if (!reuseCentral) {
    if (!/^[a-f0-9]{32}$/i.test(accountId)) throw new Error('Cloudflare Account ID 格式不正确');
    if (apiToken.length < 20) throw new Error('Cloudflare API Token 格式不正确');
  }
  await RecoveryCredentialStore.saveCloudflareConfig({ reuseCentral, accountId, apiToken });
  await RecoveryModel.addAudit('credential.cloudflare.update', { reuseCentral, accountId });
  return overview();
}

module.exports = {
  HEALTH_PATH,
  DOH_RESOLVERS,
  stableStringify,
  normalizeOrigin,
  validateDomainInput,
  validateBootstrapInput,
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
};
