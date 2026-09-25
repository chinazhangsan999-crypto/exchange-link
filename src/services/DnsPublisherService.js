'use strict';

const crypto = require('node:crypto');
const {
  Route53Client,
  ListHostedZonesByNameCommand,
  ListResourceRecordSetsCommand,
  ChangeResourceRecordSetsCommand
} = require('@aws-sdk/client-route-53');
const { dnspod } = require('tencentcloud-sdk-nodejs-dnspod');
const AliDns = require('@alicloud/alidns20150109');
const AliOpenApi = require('@alicloud/openapi-client');

const PROVIDERS = Object.freeze({
  cloudflare: { label: 'Cloudflare DNS', automaticPublish: true },
  desec: { label: 'deSEC', automaticPublish: true },
  cloudns: { label: 'ClouDNS（HTTP API 需付费套餐）', automaticPublish: true },
  route53: { label: 'AWS Route 53', automaticPublish: true },
  dnspod: { label: '腾讯云 DNSPod', automaticPublish: true },
  aliyun: { label: '阿里云云解析 DNS', automaticPublish: true },
  baidu: { label: '百度智能云 DNS', automaticPublish: true },
  volcengine: { label: '火山引擎 DNS', automaticPublish: true },
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
  if (/don't have access to the HTTP API/i.test(String(payload?.statusDescription || ''))) {
    throw new Error('ClouDNS 当前套餐不包含 HTTP API，请升级到 Premium DNS 等付费套餐后重试');
  }
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

function dnspodClient(credentials) {
  return new dnspod.v20210323.Client({
    credential: { secretId: credentials.secretId, secretKey: credentials.secretKey },
    profile: { httpProfile: { endpoint: 'dnspod.tencentcloudapi.com' } }
  });
}

async function dnspodZones(credentials) {
  const response = await dnspodClient(credentials).DescribeDomainList({ Type: 'ALL', Offset: 0, Limit: 3000 });
  return (response.DomainList || []).map(item => ({ id: String(item.DomainId || item.Domain || ''), name: String(item.Name || item.Domain || '').toLowerCase() })).filter(item => item.name);
}

async function dnspodRecords(client, zoneName, host) {
  const response = await client.DescribeRecordList({ Domain: zoneName, Subdomain: host, RecordType: 'TXT', Limit: 3000 });
  return (response.RecordList || []).filter(item => String(item.Name || '') === host && String(item.Type || '').toUpperCase() === 'TXT')
    .map(item => ({ id: String(item.RecordId), content: String(item.Value || '') }));
}

async function dnspodPublish(credentials, input) {
  const client = dnspodClient(credentials);
  const zones = await dnspodZones(credentials);
  if (!zones.some(item => item.name === input.zoneName)) throw new Error(`DNSPod 通道中未找到域名：${input.zoneName}`);
  const host = relativeRecordName(input.recordName, input.zoneName);
  const existing = await dnspodRecords(client, input.zoneName, host);
  const created = [];
  for (const value of input.values) {
    const response = await client.CreateRecord({ Domain: input.zoneName, SubDomain: host, RecordType: 'TXT', RecordLine: '默认', Value: value, TTL: 600 });
    created.push({ id: String(response.RecordId), content: value });
  }
  const remove = id => client.DeleteRecord({ Domain: input.zoneName, RecordId: Number(id) });
  return {
    resolvedZoneId: zones.find(item => item.name === input.zoneName).id,
    rollback: async () => Promise.all(created.map(item => remove(item.id).catch(() => undefined))),
    commit: async () => {
      for (const item of existing) if (isOwnedTxt(item.content) && !input.values.includes(stripTxtQuotes(item.content))) await remove(item.id);
    }
  };
}

function aliyunClient(credentials) {
  return new AliDns.default(new AliOpenApi.Config({
    accessKeyId: credentials.accessKeyId,
    accessKeySecret: credentials.accessKeySecret,
    endpoint: 'alidns.cn-hangzhou.aliyuncs.com'
  }));
}

async function aliyunZones(credentials) {
  const client = aliyunClient(credentials);
  const zones = [];
  let pageNumber = 1;
  do {
    const response = await client.describeDomains(new AliDns.DescribeDomainsRequest({ pageNumber, pageSize: 100 }));
    const page = response.body?.domains?.domain || [];
    zones.push(...page.map(item => ({ id: String(item.domainId || item.domainName || ''), name: String(item.domainName || '').toLowerCase() })));
    if (zones.length >= Number(response.body?.totalCount || zones.length)) break;
    pageNumber += 1;
  } while (pageNumber <= 100);
  return zones.filter(item => item.name);
}

async function aliyunRecords(client, zoneName, host) {
  const response = await client.describeDomainRecords(new AliDns.DescribeDomainRecordsRequest({
    domainName: zoneName, RRKeyWord: host, type: 'TXT', searchMode: 'COMBINATION', pageNumber: 1, pageSize: 500
  }));
  return (response.body?.domainRecords?.record || []).filter(item => String(item.RR || '') === host && String(item.type || '').toUpperCase() === 'TXT')
    .map(item => ({ id: String(item.recordId), content: String(item.value || '') }));
}

async function aliyunPublish(credentials, input) {
  const client = aliyunClient(credentials);
  const zones = await aliyunZones(credentials);
  if (!zones.some(item => item.name === input.zoneName)) throw new Error(`阿里云通道中未找到域名：${input.zoneName}`);
  const host = relativeRecordName(input.recordName, input.zoneName);
  const existing = await aliyunRecords(client, input.zoneName, host);
  const created = [];
  for (const value of input.values) {
    const response = await client.addDomainRecord(new AliDns.AddDomainRecordRequest({ domainName: input.zoneName, RR: host, type: 'TXT', value, TTL: 600 }));
    created.push({ id: String(response.body?.recordId || ''), content: value });
  }
  const remove = id => client.deleteDomainRecord(new AliDns.DeleteDomainRecordRequest({ recordId: id }));
  return {
    resolvedZoneId: zones.find(item => item.name === input.zoneName).id,
    rollback: async () => Promise.all(created.filter(item => item.id).map(item => remove(item.id).catch(() => undefined))),
    commit: async () => {
      for (const item of existing) if (isOwnedTxt(item.content) && !input.values.includes(stripTxtQuotes(item.content))) await remove(item.id);
    }
  };
}

async function baiduRequest(credentials, method, pathname, params = {}, body) {
  const host = 'dns.baidubce.com';
  const headers = { host, 'content-type': 'application/json; charset=utf-8' };
  const normalize = value => encodeURIComponent(String(value)).replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
  const timestamp = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const authPrefix = `bce-auth-v1/${credentials.accessKeyId}/${timestamp}/1800`;
  const signingKey = crypto.createHmac('sha256', credentials.secretAccessKey).update(authPrefix).digest('hex');
  const canonicalQuery = Object.entries(params).filter(([key, value]) => key.toLowerCase() !== 'authorization' && value !== undefined && value !== null)
    .map(([key, value]) => `${normalize(key)}=${normalize(value)}`).sort().join('&');
  const canonicalHeaders = ['content-type', 'host'].map(key => `${normalize(key)}:${normalize(headers[key].trim())}`).join('\n');
  const signature = crypto.createHmac('sha256', signingKey).update([method, pathname, canonicalQuery, canonicalHeaders].join('\n')).digest('hex');
  headers.authorization = `${authPrefix}/content-type;host/${signature}`;
  const query = new URLSearchParams(Object.entries(params).filter(([, value]) => value !== undefined).map(([key, value]) => [key, String(value)]));
  const response = await fetch(`https://${host}${pathname}${query.size ? `?${query}` : ''}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw new Error(payload?.message || payload?.Message || `百度智能云 DNS API 返回 HTTP ${response.status}`);
  return payload || {};
}

async function baiduZones(credentials) {
  const zones = [];
  let marker;
  do {
    const response = await baiduRequest(credentials, 'GET', '/v1/dns/zone', { maxKeys: 1000, ...(marker ? { marker } : {}) });
    zones.push(...(response.zones || response.zoneList || []).map(item => ({ id: String(item.id || item.zoneId || item.name || item.zoneName || ''), name: String(item.name || item.zoneName || '').toLowerCase() })));
    marker = response.isTruncated ? response.nextMarker : undefined;
  } while (marker);
  return zones.filter(item => item.name);
}

async function baiduRecords(credentials, zoneName, host) {
  const response = await baiduRequest(credentials, 'GET', `/v1/dns/zone/${encodeURIComponent(zoneName)}/record`, { rr: host, maxKeys: 1000 });
  return (response.records || response.recordList || []).filter(item => String(item.rr || item.host || '') === host && String(item.type || '').toUpperCase() === 'TXT')
    .map(item => ({ id: String(item.id || item.recordId), content: String(item.value || '') }));
}

async function baiduPublish(credentials, input) {
  const zones = await baiduZones(credentials);
  if (!zones.some(item => item.name === input.zoneName)) throw new Error(`百度智能云通道中未找到域名：${input.zoneName}`);
  const host = relativeRecordName(input.recordName, input.zoneName);
  const existing = await baiduRecords(credentials, input.zoneName, host);
  const created = [];
  for (const value of input.values) {
    await baiduRequest(credentials, 'POST', `/v1/dns/zone/${encodeURIComponent(input.zoneName)}/record`, {}, { rr: host, type: 'TXT', value, ttl: 600, line: 'default' });
    const refreshed = await baiduRecords(credentials, input.zoneName, host);
    const added = refreshed.find(item => item.content === value && !existing.some(old => old.id === item.id) && !created.some(old => old.id === item.id));
    if (!added?.id) throw new Error('百度智能云已写入 TXT，但未查询到可用于回滚的记录 ID');
    created.push(added);
  }
  const remove = id => baiduRequest(credentials, 'DELETE', `/v1/dns/zone/${encodeURIComponent(input.zoneName)}/record/${encodeURIComponent(id)}`);
  return {
    resolvedZoneId: zones.find(item => item.name === input.zoneName).id,
    rollback: async () => Promise.all(created.filter(item => item.id).map(item => remove(item.id).catch(() => undefined))),
    commit: async () => {
      for (const item of existing) if (isOwnedTxt(item.content) && !input.values.includes(stripTxtQuotes(item.content))) await remove(item.id);
    }
  };
}

async function volcengineRequest(credentials, action, body = {}) {
  const host = 'dns.volcengineapi.com';
  const region = credentials.region || 'cn-beijing';
  const service = 'dns';
  const requestBody = JSON.stringify(body);
  const dateTime = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = dateTime.slice(0, 8);
  const encode = value => encodeURIComponent(value).replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
  const query = Object.entries({ Action: action, Version: '2018-08-01' }).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => `${encode(key)}=${encode(value)}`).join('&');
  const payloadHash = crypto.createHash('sha256').update(requestBody).digest('hex');
  const headers = { host, 'content-type': 'application/json', 'X-Date': dateTime, 'X-Content-Sha256': payloadHash };
  if (credentials.sessionToken) headers['X-Security-Token'] = credentials.sessionToken;
  const signedHeaderNames = Object.keys(headers).map(key => key.toLowerCase()).filter(key => key !== 'content-type').sort();
  const canonicalHeaders = signedHeaderNames.map(key => `${key}:${headers[Object.keys(headers).find(item => item.toLowerCase() === key)].trim()}`).join('\n');
  const scope = `${date}/${region}/${service}/request`;
  const canonicalRequest = ['POST', '/', query, `${canonicalHeaders}\n`, signedHeaderNames.join(';'), payloadHash].join('\n');
  const stringToSign = ['HMAC-SHA256', dateTime, scope, crypto.createHash('sha256').update(canonicalRequest).digest('hex')].join('\n');
  const hmac = (key, value) => crypto.createHmac('sha256', key).update(value).digest();
  const signingKey = hmac(hmac(hmac(hmac(credentials.secretAccessKey, date), region), service), 'request');
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  headers.Authorization = `HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaderNames.join(';')}, Signature=${signature}`;
  const response = await fetch(`https://${host}/?${query}`, { method: 'POST', headers, body: requestBody });
  const payload = await response.json().catch(() => null);
  if (!response.ok || payload?.ResponseMetadata?.Error) throw new Error(payload?.ResponseMetadata?.Error?.Message || `火山引擎 DNS API 返回 HTTP ${response.status}`);
  return payload?.Result || payload || {};
}

async function volcengineZones(credentials) {
  const zones = [];
  let pageNumber = 1;
  do {
    const response = await volcengineRequest(credentials, 'ListZones', { PageNumber: pageNumber, PageSize: 100 });
    const page = response.Zones || response.ZoneList || [];
    zones.push(...page.map(item => ({ id: String(item.ZID || item.ZoneID || item.ID || ''), name: String(item.ZoneName || item.Name || '').toLowerCase() })));
    if (zones.length >= Number(response.TotalCount || response.Total || zones.length)) break;
    pageNumber += 1;
  } while (pageNumber <= 100);
  return zones.filter(item => item.name);
}

async function volcengineRecords(credentials, zoneId, host) {
  const response = await volcengineRequest(credentials, 'ListRecords', { ZID: Number(zoneId) || zoneId, Host: host, Type: 'TXT', PageNumber: 1, PageSize: 500 });
  return (response.Records || response.RecordList || []).filter(item => String(item.Host || item.RR || '') === host && String(item.Type || '').toUpperCase() === 'TXT')
    .map(item => ({ id: String(item.RecordID || item.RecordId || item.ID || ''), content: String(item.Value || '') }));
}

async function volcenginePublish(credentials, input) {
  const zones = await volcengineZones(credentials);
  const zone = zones.find(item => item.name === input.zoneName);
  if (!zone) throw new Error(`火山引擎通道中未找到域名：${input.zoneName}`);
  const host = relativeRecordName(input.recordName, input.zoneName);
  const existing = await volcengineRecords(credentials, zone.id, host);
  const created = [];
  for (const value of input.values) {
    const response = await volcengineRequest(credentials, 'CreateRecord', { ZID: Number(zone.id) || zone.id, Host: host, Type: 'TXT', Value: value, TTL: 600 });
    created.push({ id: String(response.RecordID || response.RecordId || response.ID || ''), content: value });
  }
  const remove = id => volcengineRequest(credentials, 'DeleteRecord', { RecordID: Number(id) || id });
  return {
    resolvedZoneId: zone.id,
    rollback: async () => Promise.all(created.filter(item => item.id).map(item => remove(item.id).catch(() => undefined))),
    commit: async () => {
      for (const item of existing) if (isOwnedTxt(item.content) && !input.values.includes(stripTxtQuotes(item.content))) await remove(item.id);
    }
  };
}

async function listZones(providerId, credentials) {
  ensureProvider(providerId);
  if (providerId === 'cloudflare') return cloudflareZones(credentials);
  if (providerId === 'desec') return desecZones(credentials);
  if (providerId === 'cloudns') return cloudnsZones(credentials);
  if (providerId === 'route53') return route53Zones(credentials);
  if (providerId === 'dnspod') return dnspodZones(credentials);
  if (providerId === 'aliyun') return aliyunZones(credentials);
  if (providerId === 'baidu') return baiduZones(credentials);
  if (providerId === 'volcengine') return volcengineZones(credentials);
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
  if (providerId === 'dnspod') return dnspodPublish(credentials, input);
  if (providerId === 'aliyun') return aliyunPublish(credentials, input);
  if (providerId === 'baidu') return baiduPublish(credentials, input);
  if (providerId === 'volcengine') return volcenginePublish(credentials, input);
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
