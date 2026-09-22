'use strict';

const {
  Route53Client,
  ListHostedZonesByNameCommand,
  ListResourceRecordSetsCommand,
  ChangeResourceRecordSetsCommand
} = require('@aws-sdk/client-route-53');

const PROVIDERS = Object.freeze({
  cloudflare: { label: 'Cloudflare DNS', automaticPublish: true },
  desec: { label: 'deSEC', automaticPublish: true },
  cloudns: { label: 'ClouDNS', automaticPublish: true },
  route53: { label: 'AWS Route 53', automaticPublish: true },
  he: { label: 'Hurricane Electric Free DNS', automaticPublish: false }
});

function providerCapabilities() {
  return Object.entries(PROVIDERS).map(([id, value]) => ({ id, ...value }));
}

function ensureProvider(providerId) {
  const provider = PROVIDERS[String(providerId || '').toLowerCase()];
  if (!provider) throw new Error('不支持该 DNS 服务商');
  return provider;
}

function stripTxtQuotes(value) {
  const text = String(value || '').trim();
  return text.startsWith('"') && text.endsWith('"') ? text.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\') : text;
}

function quoteTxt(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function isOwnedTxt(value) {
  return /^r[12];set=/.test(stripTxtQuotes(value));
}

async function jsonRequest(url, options, label) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw new Error(payload?.detail || payload?.message || `${label} API 返回 HTTP ${response.status}`);
  return payload;
}

async function cloudflareRequest(credentials, method, pathname, body) {
  const payload = await jsonRequest(`https://api.cloudflare.com/client/v4${pathname}`, {
    method,
    headers: { Authorization: `Bearer ${credentials.apiToken}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body)
  }, 'Cloudflare');
  if (payload?.success !== true) throw new Error(payload?.errors?.[0]?.message || 'Cloudflare API 请求失败');
  return payload.result;
}

async function cloudflareZones(credentials) {
  const result = await cloudflareRequest(credentials, 'GET', `/zones?status=active&account.id=${encodeURIComponent(credentials.accountId)}&per_page=50`);
  return result.map(item => ({ id: item.id, name: String(item.name).toLowerCase() }));
}

async function cloudflarePublish(credentials, input) {
  const zones = await cloudflareZones(credentials);
  const zone = zones.find(item => item.name === input.zoneName);
  if (!zone) throw new Error(`Cloudflare 通道中未找到 Active Zone：${input.zoneName}`);
  const existing = await cloudflareRequest(credentials, 'GET', `/zones/${zone.id}/dns_records?type=TXT&name=${encodeURIComponent(input.recordName)}&per_page=100`);
  const created = [];
  for (const content of input.values) {
    created.push(await cloudflareRequest(credentials, 'POST', `/zones/${zone.id}/dns_records`, {
      type: 'TXT', name: input.recordName, content, ttl: 60,
      comment: `navigation recovery generation ${input.generation}`
    }));
  }
  return {
    resolvedZoneId: zone.id,
    rollback: async () => Promise.all(created.map(item => item?.id
      ? cloudflareRequest(credentials, 'DELETE', `/zones/${zone.id}/dns_records/${encodeURIComponent(item.id)}`).catch(() => undefined)
      : undefined)),
    commit: async () => {
      for (const item of existing) {
        if (isOwnedTxt(item.content) && !input.values.includes(stripTxtQuotes(item.content))) {
          await cloudflareRequest(credentials, 'DELETE', `/zones/${zone.id}/dns_records/${encodeURIComponent(item.id)}`);
        }
      }
    }
  };
}

async function desecRequest(credentials, method, pathname, body, allowNotFound = false) {
  const response = await fetch(`https://desec.io/api/v1${pathname}`, {
    method,
    headers: { Authorization: `Token ${credentials.apiToken}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  if (allowNotFound && response.status === 404) return null;
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw new Error(payload?.detail || payload?.non_field_errors?.[0] || `deSEC API 返回 HTTP ${response.status}`);
  return payload;
}

async function desecZones(credentials) {
  const result = await desecRequest(credentials, 'GET', '/domains/?limit=500');
  const items = Array.isArray(result) ? result : (result?.results || []);
  return items.map(item => ({ id: item.name, name: String(item.name).toLowerCase() }));
}

function relativeRecordName(recordName, zoneName) {
  if (recordName === zoneName) return '@';
  if (!recordName.endsWith(`.${zoneName}`)) throw new Error('TXT 记录不属于所选 Zone');
  return recordName.slice(0, -(zoneName.length + 1));
}

async function desecPublish(credentials, input) {
  const zones = await desecZones(credentials);
  if (!zones.some(item => item.name === input.zoneName)) throw new Error(`deSEC 通道中未找到 Zone：${input.zoneName}`);
  const subname = relativeRecordName(input.recordName, input.zoneName);
  const endpoint = `/domains/${encodeURIComponent(input.zoneName)}/rrsets/${encodeURIComponent(subname)}/TXT/`;
  const existing = await desecRequest(credentials, 'GET', endpoint, undefined, true);
  const preserved = (existing?.records || []).filter(value => !isOwnedTxt(value));
  const next = [...preserved, ...input.values.map(quoteTxt)];
  const body = { subname: subname === '@' ? '' : subname, type: 'TXT', ttl: 60, records: next };
  if (existing) await desecRequest(credentials, 'PUT', endpoint, body);
  else await desecRequest(credentials, 'POST', `/domains/${encodeURIComponent(input.zoneName)}/rrsets/`, body);
  return {
    resolvedZoneId: input.zoneName,
    rollback: async () => {
      if (existing) await desecRequest(credentials, 'PUT', endpoint, existing);
      else await desecRequest(credentials, 'DELETE', endpoint);
    },
    commit: async () => undefined
  };
}

function cloudnsAuth(credentials) {
  const type = ['auth-id', 'sub-auth-id', 'sub-auth-user'].includes(credentials.authType) ? credentials.authType : 'auth-id';
  return { [type]: credentials.authId, 'auth-password': credentials.authPassword };
}

async function cloudnsRequest(credentials, pathname, parameters = {}) {
  const body = new URLSearchParams({ ...cloudnsAuth(credentials), ...parameters });
  const payload = await jsonRequest(`https://api.cloudns.net${pathname}`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body
  }, 'ClouDNS');
  if (payload?.status === 'Failed') throw new Error(payload.statusDescription || 'ClouDNS API 请求失败');
  return payload;
}

async function cloudnsZones(credentials) {
  const result = await cloudnsRequest(credentials, '/dns/list-zones.json', { page: '1', 'rows-per-page': '100' });
  return Object.entries(result || {}).filter(([, item]) => item && typeof item === 'object')
    .map(([id, item]) => ({ id: String(item.id || id), name: String(item.name || item.zone || '').toLowerCase() }))
    .filter(item => item.name);
}

async function cloudnsRecords(credentials, zoneName, host) {
  const result = await cloudnsRequest(credentials, '/dns/records.json', { 'domain-name': zoneName, host, type: 'TXT', page: '1', 'rows-per-page': '100' });
  return Object.entries(result || {}).filter(([, item]) => item && typeof item === 'object')
    .map(([id, item]) => ({ id: String(item.id || id), content: String(item.record || item.value || ''), host: String(item.host || host) }));
}

async function cloudnsDelete(credentials, zoneName, id) {
  await cloudnsRequest(credentials, '/dns/delete-record.json', { 'domain-name': zoneName, 'record-id': String(id) });
}

async function cloudnsPublish(credentials, input) {
  const zones = await cloudnsZones(credentials);
  if (!zones.some(item => item.name === input.zoneName)) throw new Error(`ClouDNS 通道中未找到 Zone：${input.zoneName}`);
  const host = relativeRecordName(input.recordName, input.zoneName);
  const existing = await cloudnsRecords(credentials, input.zoneName, host);
  const created = [];
  for (const value of input.values) {
    const response = await cloudnsRequest(credentials, '/dns/add-record.json', {
      'domain-name': input.zoneName, 'record-type': 'TXT', host, record: value, ttl: '60'
    });
    let id = response?.data?.id || response?.id;
    if (!id) {
      const refreshed = await cloudnsRecords(credentials, input.zoneName, host);
      id = refreshed.find(item => item.content === value && !existing.some(old => old.id === item.id) && !created.some(old => old.id === item.id))?.id;
    }
    if (!id) throw new Error('ClouDNS 已写入 TXT，但未返回可用于回滚的记录 ID');
    created.push({ id: String(id), content: value });
  }
  return {
    resolvedZoneId: input.zoneName,
    rollback: async () => Promise.all(created.map(item => cloudnsDelete(credentials, input.zoneName, item.id).catch(() => undefined))),
    commit: async () => {
      for (const item of existing) if (isOwnedTxt(item.content) && !input.values.includes(stripTxtQuotes(item.content))) await cloudnsDelete(credentials, input.zoneName, item.id);
    }
  };
}

function route53Client(credentials) {
  return new Route53Client({
    region: 'us-east-1',
    credentials: {
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey,
      ...(credentials.sessionToken ? { sessionToken: credentials.sessionToken } : {})
    }
  });
}

async function route53Zones(credentials) {
  const client = route53Client(credentials);
  const result = await client.send(new ListHostedZonesByNameCommand({ MaxItems: 100 }));
  return (result.HostedZones || []).map(item => ({ id: String(item.Id || '').replace(/^\/hostedzone\//, ''), name: String(item.Name || '').toLowerCase().replace(/\.$/, '') }));
}

async function route53Change(client, zoneId, action, recordSet) {
  return client.send(new ChangeResourceRecordSetsCommand({
    HostedZoneId: zoneId,
    ChangeBatch: { Changes: [{ Action: action, ResourceRecordSet: recordSet }] }
  }));
}

async function route53Publish(credentials, input) {
  const client = route53Client(credentials);
  const zones = await route53Zones(credentials);
  const zone = zones.find(item => item.name === input.zoneName);
  if (!zone) throw new Error(`Route 53 通道中未找到 Hosted Zone：${input.zoneName}`);
  const response = await client.send(new ListResourceRecordSetsCommand({ HostedZoneId: zone.id, StartRecordName: input.recordName, StartRecordType: 'TXT', MaxItems: 1 }));
  const candidate = response.ResourceRecordSets?.[0];
  const existing = candidate && String(candidate.Name).toLowerCase().replace(/\.$/, '') === input.recordName && candidate.Type === 'TXT' ? candidate : null;
  const preserved = (existing?.ResourceRecords || []).map(item => item.Value).filter(value => !isOwnedTxt(value));
  const next = {
    Name: input.recordName,
    Type: 'TXT',
    TTL: 60,
    ResourceRecords: [...preserved, ...input.values.map(quoteTxt)].map(Value => ({ Value }))
  };
  await route53Change(client, zone.id, 'UPSERT', next);
  return {
    resolvedZoneId: zone.id,
    rollback: async () => existing
      ? route53Change(client, zone.id, 'UPSERT', existing)
      : route53Change(client, zone.id, 'DELETE', next),
    commit: async () => undefined
  };
}

async function listZones(providerId, credentials) {
  ensureProvider(providerId);
  if (providerId === 'cloudflare') return cloudflareZones(credentials);
  if (providerId === 'desec') return desecZones(credentials);
  if (providerId === 'cloudns') return cloudnsZones(credentials);
  if (providerId === 'route53') return route53Zones(credentials);
  throw new Error('该服务商当前不支持 API 自动发布');
}

async function verifyChannel(providerId, credentials) {
  const zones = await listZones(providerId, credentials);
  return { ok: true, zoneCount: zones.length, zones };
}

async function createPublishOperation(providerId, credentials, input) {
  const provider = ensureProvider(providerId);
  if (!provider.automaticPublish) throw new Error('该服务商当前不支持 API 自动发布');
  if (providerId === 'cloudflare') return cloudflarePublish(credentials, input);
  if (providerId === 'desec') return desecPublish(credentials, input);
  if (providerId === 'cloudns') return cloudnsPublish(credentials, input);
  if (providerId === 'route53') return route53Publish(credentials, input);
  throw new Error('该服务商尚未实现自动发布适配器');
}

module.exports = {
  providerCapabilities,
  verifyChannel,
  listZones,
  createPublishOperation,
  isOwnedTxt,
  stripTxtQuotes
};
