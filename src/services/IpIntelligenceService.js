'use strict';

const crypto = require('crypto');
const axios = require('axios');
const IpProfileModel = require('../models/IpProfileModel');
const { IP_INTELLIGENCE_TIMEOUT_MS, IP_INTELLIGENCE_BATCH_SIZE } = require('../config/env');
const CredentialStore = require('./IntegrationCredentialStore');

const LOOKUP_PATH = '/v1/ip/lookup';
const WORK_INTERVAL_MS = 10_000;
let timer = null;
let running = false;
let stopping = false;
let runtimeConfig = CredentialStore.ipIntelligenceConfig();
let lastConnectedAt = null;
let lastError = '';

function normalizeConfig(input = {}, current = runtimeConfig) {
  const enabled = input.enabled === undefined ? current.enabled !== false
    : ['1', 'true', 'on', 'yes'].includes(String(input.enabled).toLowerCase());
  const baseUrl = String(input.baseUrl || input.base_url || current.baseUrl || '').trim().replace(/\/$/, '');
  const clientId = String(input.clientId || input.client_id || current.clientId || '').trim();
  const secret = String(input.secret || current.secret || '').trim();
  let parsed;
  try { parsed = new URL(baseUrl); } catch { throw new Error('IP 情报服务地址格式不正确'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('IP 情报服务地址必须是 HTTPS Origin');
  }
  if (!clientId || clientId.length > 128) throw new Error('Client ID 不能为空且不能超过 128 字符');
  if (secret.length < 24 || secret.length > 512) throw new Error('Client Secret 长度不合法');
  return { enabled, baseUrl, clientId, secret };
}

function isEnabled(config = runtimeConfig) {
  return config.enabled !== false && Boolean(config.baseUrl && config.clientId && config.secret);
}

function signatureFor(body, timestamp, nonce, config = runtimeConfig) {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const canonical = ['POST', LOOKUP_PATH, timestamp, nonce, bodyHash].join('\n');
  return crypto.createHmac('sha256', config.secret).update(canonical).digest('hex');
}

function sourceVersion(meta = {}) {
  return Object.entries(meta.database_versions || {}).map(([name, version]) => `${name}:${version}`).join(', ');
}

async function lookupBatch(ips, config = runtimeConfig) {
  const active = normalizeConfig(config, config);
  const body = JSON.stringify({ ips });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();
  const response = await axios.post(`${active.baseUrl}${LOOKUP_PATH}`, body, {
    timeout: IP_INTELLIGENCE_TIMEOUT_MS,
    validateStatus: () => true,
    headers: {
      'content-type': 'application/json',
      'x-client-id': active.clientId,
      'x-timestamp': timestamp,
      'x-nonce': nonce,
      'x-signature': signatureFor(body, timestamp, nonce, active)
    }
  });
  const payload = response.data && typeof response.data === 'object' ? response.data : {};
  if (response.status < 200 || response.status >= 300 || payload.code !== 'OK' || !Array.isArray(payload.data)) {
    throw new Error(`中心服务返回 ${response.status} / ${payload.code || 'UNKNOWN'}`);
  }
  return payload;
}

async function testConfig(input) {
  const config = normalizeConfig(input);
  const payload = await lookupBatch(['1.1.1.1'], config);
  lastConnectedAt = new Date().toISOString();
  lastError = '';
  return { config, resultCount: payload.data.length };
}

async function saveAndReconfigure(input) {
  const { config } = await testConfig(input);
  await CredentialStore.saveIpIntelligence(config);
  runtimeConfig = config;
  if (!timer) start();
  return status();
}

function status() {
  return {
    enabled: isEnabled(),
    baseUrl: runtimeConfig.baseUrl || '',
    clientId: runtimeConfig.clientId || '',
    secretConfigured: Boolean(runtimeConfig.secret),
    lastConnectedAt,
    lastError: lastError ? 'IP 情报服务暂时不可用' : ''
  };
}

async function processDue() {
  if (!isEnabled() || running || stopping) return;
  running = true;
  try {
    const rows = await IpProfileModel.listDue(IP_INTELLIGENCE_BATCH_SIZE);
    if (!rows.length) return;
    let payload;
    try {
      payload = await lookupBatch(rows.map(row => row.ip_key));
      lastConnectedAt = new Date().toISOString();
      lastError = '';
    } catch (error) {
      lastError = String(error?.message || error);
      const reason = error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT' ? '中心 IP 查询超时' : lastError;
      await Promise.all(rows.map(row => IpProfileModel.saveFailure(row.ip_key, reason, Number(row.failure_count || 0) + 1)));
      console.warn(`[IP 情报] ${reason}，已进入后台退避，不影响访客请求。`);
      return;
    }
    const resultMap = new Map(payload.data.map(item => [String(item.input || ''), item]));
    const version = sourceVersion(payload.meta);
    await Promise.all(rows.map(row => {
      const result = resultMap.get(row.ip_key);
      if (!result) return IpProfileModel.saveFailure(row.ip_key, '中心响应缺少该 IP 结果', Number(row.failure_count || 0) + 1);
      if (result.status === 'resolved') return IpProfileModel.saveResolved(row.ip_key, result, version);
      if (result.status === 'invalid') return IpProfileModel.saveInvalid(row.ip_key, result.message);
      return IpProfileModel.saveFailure(row.ip_key, result.message || '中心数据源暂不可用', Number(row.failure_count || 0) + 1);
    }));
  } catch (error) {
    lastError = String(error?.message || error);
    console.warn('[IP 情报] 后台处理失败：', lastError);
  } finally { running = false; }
}

function queueIp(ip) {
  if (!isEnabled() || stopping) return;
  void IpProfileModel.enqueue(ip).then(() => processDue())
    .catch(error => console.warn('[IP 情报] 登记待查询 IP 失败：', error.message));
}

function start() {
  if (!isEnabled() || timer) return;
  stopping = false;
  void IpProfileModel.enqueueExistingLogIps().then(() => processDue())
    .catch(error => console.warn('[IP 情报] 历史 IP 入队失败：', error.message));
  timer = setInterval(() => { void processDue(); }, WORK_INTERVAL_MS);
  timer.unref?.();
  console.log(`[IP 情报] 已启用中心查询：${runtimeConfig.baseUrl}`);
}

async function stop() {
  stopping = true;
  if (timer) clearInterval(timer);
  timer = null;
  const deadline = Date.now() + Math.min(IP_INTELLIGENCE_TIMEOUT_MS + 1000, 5000);
  while (running && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 50));
}

module.exports = { start, stop, queueIp, processDue, signatureFor, lookupBatch, testConfig, saveAndReconfigure, status };
