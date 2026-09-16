'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Blob } = require('buffer');
const CredentialStore = require('./IntegrationCredentialStore');
const CloudflareFrontendModel = require('../models/CloudflareFrontendModel');
const { FRONTEND_PROXY_SECRET } = require('../config/env');

const API_BASE = 'https://api.cloudflare.com/client/v4';
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const PUBLIC_DIRECTORY = path.join(PROJECT_ROOT, 'public');
const PUBLIC_WORKER_SOURCE = path.join(PROJECT_ROOT, 'ops', 'public-edge', 'worker.js');
const API_ORIGIN = String(process.env.PUBLIC_API_ORIGIN || 'https://api-link.chinazhangsan.ccwu.cc').trim().replace(/\/$/, '');
const HOSTNAME_PATTERN = /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const PROFILE_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const WORKER_PREFIX_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,54}$/;
const MIME_TYPES = { '.css': 'text/css', '.gif': 'image/gif', '.html': 'text/html', '.ico': 'image/x-icon', '.jpeg': 'image/jpeg', '.jpg': 'image/jpeg', '.js': 'application/javascript', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.txt': 'text/plain', '.webp': 'image/webp', '.woff': 'font/woff', '.woff2': 'font/woff2' };
const RUN_WORKER_FIRST = ['/', '/index.html', '/r/*', '/api/*', '/go', '/favicon.ico', '/uploads/logo/*'];

let provisioningTail = Promise.resolve();

function tokenFingerprint(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex').slice(-8).toUpperCase();
}

function parseJson(value, fallback) {
  try { return value ? JSON.parse(value) : fallback; } catch { return fallback; }
}

function normalizeHostname(value) {
  const hostname = String(value || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/\.$/, '');
  if (!HOSTNAME_PATTERN.test(hostname)) throw new Error('前台域名格式不正确');
  return hostname;
}

function normalizeProfile(input = {}, existing = {}) {
  const id = String(input.id ?? existing.id ?? '').trim().toLowerCase();
  const label = String(input.label ?? existing.label ?? '').trim();
  const accountId = String(input.accountId ?? existing.accountId ?? '').trim();
  // 兼容上一版已保存的固定 Worker 名称；管理员下次保存后即转换为前缀模式。
  const workerPrefix = String(input.workerPrefix ?? existing.workerPrefix ?? existing.workerName ?? '').trim();
  const apiToken = String(input.apiToken || existing.apiToken || '').trim();
  if (!PROFILE_PATTERN.test(id)) throw new Error('账号配置标识只能使用小写字母、数字、连字符或下划线');
  if (!label || label.length > 80) throw new Error('账号显示名称需为 1 到 80 个字符');
  if (!/^[a-f0-9]{32}$/i.test(accountId)) throw new Error('Cloudflare Account ID 格式不正确');
  if (!WORKER_PREFIX_PATTERN.test(workerPrefix)) throw new Error('Worker 前缀格式不正确，最多 55 个字母、数字、点、下划线或连字符');
  if (apiToken.length < 20 || apiToken.length > 512) throw new Error('Cloudflare API Token 格式不正确');
  return { id, label, accountId, workerPrefix, apiToken };
}

function resolveProfileCredential(profile) {
  if (profile?.credentialSource !== 'central') return profile;
  const central = CredentialStore.cloudflareApiEdgeConfig();
  return { ...profile, accountId: central.accountId, apiToken: central.apiToken };
}

function runtimeProfiles() {
  return CredentialStore.cloudflarePublicFrontendProfiles().map(resolveProfileCredential);
}

function publicProfile(profile, account = null, workers = []) {
  return {
    id: profile.id,
    label: profile.label,
    accountId: profile.accountId,
    workerPrefix: profile.workerPrefix || profile.workerName || '',
    credentialSource: profile.credentialSource || 'account',
    apiTokenConfigured: Boolean(profile.apiToken),
    tokenFingerprint: account?.token_fingerprint || (profile.apiToken ? tokenFingerprint(profile.apiToken) : null),
    tokenStatus: account?.token_status || 'unverified',
    lastVerifiedAt: account?.last_verified_at || null,
    lastError: account?.last_error || null,
    allocationEnabled: account ? Number(account.allocation_enabled) === 1 : true,
    enabled: account ? Number(account.enabled) === 1 : true,
    activeZones: parseJson(account?.active_zones_json, []),
    initialized: Boolean(workers.some(worker => worker.account_profile_id === profile.id && worker.hostname == null && worker.state === 'ready')),
    nextWorkerNumber: Number(account?.next_worker_number || 1),
    workers: workers.filter(worker => worker.account_profile_id === profile.id).map(worker => ({
      workerName: worker.worker_name,
      hostname: worker.hostname,
      zoneName: worker.zone_name,
      id: worker.id,
      domainId: worker.cloudflare_domain_id || null,
      state: worker.state,
      health: parseJson(worker.health_json, null),
      lastHealthAt: worker.last_health_at || null,
      lastDeployedAt: worker.last_deployed_at || null,
      migrationState: worker.migration_state || 'none',
      error: worker.error_message || null,
      createdAt: worker.created_at,
      updatedAt: worker.updated_at
    }))
  };
}

async function listProfiles() {
  const [accounts, workers] = await Promise.all([CloudflareFrontendModel.listAccounts(), CloudflareFrontendModel.listWorkers()]);
  const accountMap = new Map(accounts.map(account => [account.id, account]));
  return runtimeProfiles().map(profile => publicProfile(profile, accountMap.get(profile.id), workers));
}

async function adoptStoredProfiles() {
  for (const [index, profile] of runtimeProfiles().entries()) {
    if (await CloudflareFrontendModel.getAccount(profile.id)) continue;
    await CloudflareFrontendModel.upsertAccount({
      ...profile, tokenFingerprint: tokenFingerprint(profile.apiToken), tokenStatus: 'unverified',
      activeZones: [], isPrimary: index === 0
    });
  }
}

async function request(profile, method, apiPath, { body, headers = {} } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);
  try {
    const response = await fetch(`${API_BASE}${apiPath}`, {
      method,
      headers: { Authorization: `Bearer ${profile.apiToken}`, ...headers },
      body,
      signal: controller.signal
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok || !payload?.success) {
      throw new Error(payload?.errors?.[0]?.message || `Cloudflare API 请求失败（HTTP ${response.status}）`);
    }
    return payload.result ?? {};
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('连接 Cloudflare API 超时');
    throw error;
  } finally { clearTimeout(timeout); }
}

async function listActiveZones(profile) {
  const zones = [];
  for (let page = 1; page <= 20; page += 1) {
    const result = await request(profile, 'GET', `/zones?account.id=${encodeURIComponent(profile.accountId)}&status=active&per_page=50&page=${page}`);
    const entries = Array.isArray(result) ? result : [];
    zones.push(...entries.map(item => String(item.name || '').toLowerCase()).filter(name => HOSTNAME_PATTERN.test(name)));
    if (entries.length < 50) break;
  }
  if (!zones.length) throw new Error('此 Cloudflare 账号未发现处于 Active 状态的托管根域名');
  return [...new Set(zones)];
}

async function verifyProfile(profile) {
  await request(profile, 'GET', '/user/tokens/verify');
  return listActiveZones(profile);
}

function findProfile(id) {
  const profile = runtimeProfiles().find(item => item.id === id);
  if (!profile) throw new Error('公共前台 Cloudflare 账号不存在');
  return profile;
}

function withProvisioningLock(work) {
  const next = provisioningTail.then(work, work);
  provisioningTail = next.catch(() => undefined);
  return next;
}

function collectAssets(directory = PUBLIC_DIRECTORY) {
  const assets = [];
  function walk(current, relative = '') {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const nextRelative = relative ? path.posix.join(relative, entry.name) : entry.name;
      if (entry.isDirectory()) {
        if (nextRelative.toLowerCase() !== 'admin') walk(path.join(current, entry.name), nextRelative);
        continue;
      }
      if (!entry.isFile() || nextRelative.toLowerCase().endsWith('.map')) continue;
      const content = fs.readFileSync(path.join(current, entry.name));
      const hash = crypto.createHash('sha256').update(content).digest('hex').slice(0, 32);
      assets.push({ path: `/${nextRelative}`, hash, content, contentType: MIME_TYPES[path.extname(entry.name).toLowerCase()] || 'application/octet-stream' });
    }
  }
  walk(directory);
  if (!assets.some(asset => asset.path === '/index.html')) throw new Error('公共前台构建源缺少 index.html');
  return assets;
}

async function uploadAndDeploy(profile, workerName) {
  if (!FRONTEND_PROXY_SECRET || FRONTEND_PROXY_SECRET.length < 32) throw new Error('源站未配置 FRONTEND_PROXY_SECRET，已拒绝创建前台 Worker');
  const source = await fs.promises.readFile(PUBLIC_WORKER_SOURCE, 'utf8');
  const assets = collectAssets();
  const byHash = new Map(assets.map(asset => [asset.hash, asset]));
  const manifest = Object.fromEntries(assets.map(asset => [asset.path, { hash: asset.hash, size: asset.content.length }]));
  const session = await request(profile, 'POST', `/accounts/${encodeURIComponent(profile.accountId)}/workers/scripts/${encodeURIComponent(workerName)}/assets-upload-session`, {
    body: JSON.stringify({ manifest }), headers: { 'Content-Type': 'application/json' }
  });
  let completionJwt = String(session.jwt || '');
  if (!completionJwt) throw new Error('Cloudflare 未返回静态资源上传凭据');
  for (const bucket of (session.buckets || [])) {
    const form = new FormData();
    for (const hash of bucket) {
      const asset = byHash.get(hash);
      if (!asset) throw new Error('Cloudflare 返回了未知的静态资源上传任务');
      form.append(hash, new Blob([asset.content.toString('base64')], { type: asset.contentType }), asset.path.slice(1));
    }
    const uploaded = await request({ apiToken: completionJwt }, 'POST', `/accounts/${encodeURIComponent(profile.accountId)}/workers/assets/upload?base64=true`, { body: form });
    completionJwt = String(uploaded.jwt || '');
    if (!completionJwt) throw new Error('Cloudflare 未返回静态资源完成凭据');
  }
  const metadata = {
    main_module: 'worker.js',
    compatibility_date: '2026-09-14',
    bindings: [
      { name: 'ASSETS', type: 'assets' },
      { name: 'API_ORIGIN', type: 'plain_text', text: API_ORIGIN }
    ],
    assets: { jwt: completionJwt, config: { run_worker_first: RUN_WORKER_FIRST } }
  };
  const deployment = new FormData();
  deployment.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }), 'metadata.json');
  deployment.append('worker.js', new Blob([source], { type: 'application/javascript' }), 'worker.js');
  await request(profile, 'PUT', `/accounts/${encodeURIComponent(profile.accountId)}/workers/scripts/${encodeURIComponent(workerName)}`, { body: deployment });
  await request(profile, 'PUT', `/accounts/${encodeURIComponent(profile.accountId)}/workers/scripts/${encodeURIComponent(workerName)}/secrets`, {
    body: JSON.stringify({ name: 'FRONTEND_PROXY_SECRET', text: FRONTEND_PROXY_SECRET, type: 'secret_text' }),
    headers: { 'Content-Type': 'application/json' }
  });
}

async function provisionReservedWorker(profile, reservation) {
  try {
    await uploadAndDeploy(profile, reservation.workerName);
    return reservation;
  } catch (error) {
    await CloudflareFrontendModel.updateWorker(reservation.id, { state: 'failed', errorMessage: error.message });
    throw error;
  }
}

async function initializeProfile(profile) {
  const existing = (await CloudflareFrontendModel.listWorkers())
    .find(worker => worker.account_profile_id === profile.id && worker.hostname == null && worker.state === 'ready');
  if (existing) return { workerName: existing.worker_name, created: false };
  const reservation = await CloudflareFrontendModel.reserveWorker(profile.id);
  await withProvisioningLock(() => provisionReservedWorker(profile, reservation));
  await CloudflareFrontendModel.updateWorker(reservation.id, { state: 'ready' });
  return { workerName: reservation.workerName, created: true };
}

async function saveProfile(input = {}, options = {}) {
  const profiles = CredentialStore.cloudflarePublicFrontendProfiles();
  const storedExisting = profiles.find(profile => profile.id === String(input.id || '').trim().toLowerCase()) || {};
  const existing = resolveProfileCredential(storedExisting);
  let profileInput = input;
  if (input.reuseCentralCredential === true) {
    const central = CredentialStore.cloudflareApiEdgeConfig();
    if (!central.accountId || !central.apiToken) throw new Error('中央 Cloudflare 凭据尚未配置，无法复用');
    profileInput = { ...input, accountId: central.accountId, apiToken: central.apiToken };
  }
  const profile = normalizeProfile(profileInput, existing);
  const storedAccount = await CloudflareFrontendModel.getAccount(profile.id);
  if (storedAccount && storedAccount.account_id !== profile.accountId) {
    const hasWorkers = (await CloudflareFrontendModel.listWorkers()).some(worker => worker.account_profile_id === profile.id);
    if (hasWorkers) throw new Error('该账号已创建 Worker，Account ID 已锁定；请添加新的账号配置');
  }
  const activeZones = await verifyProfile(profile);
  const next = profiles.filter(item => item.id !== profile.id);
  next.push(input.reuseCentralCredential === true
    ? { ...profile, apiToken: '', credentialSource: 'central' }
    : { ...profile, credentialSource: 'account' });
  await CredentialStore.saveCloudflarePublicFrontendProfiles(next);
  let upserted;
  try {
    upserted = await CloudflareFrontendModel.upsertAccount({
      ...profile,
      tokenFingerprint: tokenFingerprint(profile.apiToken),
      tokenStatus: 'valid',
      activeZones,
      isPrimary: options.isPrimary === true
    });
  } catch (error) {
    await CredentialStore.saveCloudflarePublicFrontendProfiles(profiles).catch(() => undefined);
    throw error;
  }
  let initialization = null;
  if (upserted.created && options.skipInitialization !== true) {
    try { initialization = await initializeProfile(profile); }
    catch (error) { initialization = { created: false, error: error.message }; }
  }
  return { ...publicProfile(profile, upserted.account, await CloudflareFrontendModel.listWorkers()), initialization };
}

async function resolveProfileForHostname(hostname, preferredProfileId = null) {
  const profiles = runtimeProfiles();
  const candidates = [];
  for (const profile of profiles) {
    if (preferredProfileId && profile.id !== preferredProfileId) continue;
    const account = await CloudflareFrontendModel.getAccount(profile.id);
    if (!account || Number(account.enabled) !== 1 || Number(account.allocation_enabled) !== 1) continue;
    for (const zone of await listActiveZones(profile)) {
      if (hostname.endsWith(`.${zone}`)) candidates.push({ profile, zone });
      if (hostname === zone) throw new Error('为防止覆盖根站点，只允许创建已托管根域名的子域名前台');
    }
  }
  candidates.sort((left, right) => right.zone.length - left.zone.length);
  if (!candidates.length) throw new Error('未在已配置 Cloudflare 账号的 Active Zone 中找到该前台域名');
  if (candidates.length > 1 && candidates[0].zone === candidates[1].zone && candidates[0].profile.id !== candidates[1].profile.id) {
    throw new Error('该根域名在多个 Cloudflare 账号中重复出现，无法安全自动选择');
  }
  return { hostname, profile: candidates[0].profile, zone: candidates[0].zone };
}

async function createDedicatedFrontend(hostnameInput, preferredProfileId = null) {
  const hostname = normalizeHostname(hostnameInput);
  const resolved = await resolveProfileForHostname(hostname, preferredProfileId);
  const reservation = await CloudflareFrontendModel.reserveWorker(resolved.profile.id, hostname, resolved.zone);
  let domain = null;
  try {
    await withProvisioningLock(() => provisionReservedWorker(resolved.profile, reservation));
    domain = await request(resolved.profile, 'PUT', `/accounts/${encodeURIComponent(resolved.profile.accountId)}/workers/domains`, {
      body: JSON.stringify({ hostname, service: reservation.workerName, zone_name: resolved.zone }),
      headers: { 'Content-Type': 'application/json' }
    });
    return { ...reservation, profileId: resolved.profile.id, accountId: resolved.profile.accountId, hostname, zone: resolved.zone, domainId: domain.id };
  } catch (error) {
    if (domain?.id) await request(resolved.profile, 'DELETE', `/accounts/${encodeURIComponent(resolved.profile.accountId)}/workers/domains/${encodeURIComponent(domain.id)}`).catch(() => undefined);
    await request(resolved.profile, 'DELETE', `/accounts/${encodeURIComponent(resolved.profile.accountId)}/workers/scripts/${encodeURIComponent(reservation.workerName)}`).catch(() => undefined);
    await CloudflareFrontendModel.updateWorker(reservation.id, { state: 'failed', errorMessage: error.message });
    throw error;
  }
}

async function finalizeDedicatedFrontend(reservation, health) {
  await CloudflareFrontendModel.updateWorker(reservation.id, {
    state: 'ready', health, domainId: reservation.domainId || null, deployed: true
  });
}

async function rollbackDedicatedFrontend(reservation, reason) {
  if (!reservation) return;
  const profile = findProfile(reservation.profileId);
  if (reservation.domainId) await request(profile, 'DELETE', `/accounts/${encodeURIComponent(profile.accountId)}/workers/domains/${encodeURIComponent(reservation.domainId)}`).catch(() => undefined);
  await request(profile, 'DELETE', `/accounts/${encodeURIComponent(profile.accountId)}/workers/scripts/${encodeURIComponent(reservation.workerName)}`).catch(() => undefined);
  await CloudflareFrontendModel.updateWorker(reservation.id, { state: 'failed', errorMessage: reason || '创建流程已回滚' });
}

async function checkHealth(hostname) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const [page, health] = await Promise.all([
      fetch(`https://${hostname}/robots.txt`, { signal: controller.signal, redirect: 'manual' }),
      fetch(`https://${hostname}/api/health`, { signal: controller.signal, redirect: 'manual' })
    ]);
    return { healthy: page.ok && health.ok, pageStatus: page.status, apiStatus: health.status };
  } catch (error) {
    return { healthy: false, error: error.name === 'AbortError' ? '健康检查超时' : '健康检查无法连接' };
  } finally { clearTimeout(timeout); }
}

async function verifyAccount(id) {
  const profile = findProfile(id);
  try {
    const activeZones = await verifyProfile(profile);
    await CloudflareFrontendModel.updateAccountVerification(id, {
      status: 'valid', tokenFingerprint: tokenFingerprint(profile.apiToken), activeZones
    });
    return { id, status: 'valid', activeZones, verifiedAt: new Date().toISOString() };
  } catch (error) {
    await CloudflareFrontendModel.updateAccountVerification(id, { status: 'invalid', error: error.message });
    throw error;
  }
}

async function setAccountAllocation(id, enabled) {
  if (!await CloudflareFrontendModel.getAccount(id)) throw new Error('Cloudflare 账号配置不存在');
  await CloudflareFrontendModel.setAccountAllocation(id, enabled);
  return { id, allocationEnabled: Boolean(enabled) };
}

async function updateAccountToken(id, apiToken) {
  const current = findProfile(id);
  return saveProfile({
    id: current.id, label: current.label, accountId: current.accountId,
    workerPrefix: current.workerPrefix || current.workerName, apiToken
  }, { skipInitialization: true });
}

async function healthCheckWorker(id) {
  const worker = await CloudflareFrontendModel.getWorker(id);
  if (!worker || !worker.hostname) throw new Error('前台 Worker 不存在或尚未绑定域名');
  const health = await checkHealth(worker.hostname);
  await CloudflareFrontendModel.updateWorker(id, {
    state: health.healthy ? 'ready' : 'failed', health,
    errorMessage: health.healthy ? null : (health.error || '健康检查未通过')
  });
  return health;
}

async function redeployWorker(id) {
  const worker = await CloudflareFrontendModel.getWorker(id);
  if (!worker) throw new Error('前台 Worker 不存在');
  const profile = findProfile(worker.account_profile_id);
  await withProvisioningLock(() => uploadAndDeploy(profile, worker.worker_name));
  const health = worker.hostname ? await checkHealth(worker.hostname) : null;
  await CloudflareFrontendModel.updateWorker(id, {
    state: health && !health.healthy ? 'failed' : 'ready',
    health: health || undefined, deployed: true,
    errorMessage: health && !health.healthy ? (health.error || '部署完成但健康检查未通过') : null
  });
  return { id, workerName: worker.worker_name, health };
}

async function reconcileAccount(id) {
  const profile = findProfile(id);
  const [domains, scripts, activeZones] = await Promise.all([
    request(profile, 'GET', `/accounts/${encodeURIComponent(profile.accountId)}/workers/domains`),
    request(profile, 'GET', `/accounts/${encodeURIComponent(profile.accountId)}/workers/scripts`),
    listActiveZones(profile)
  ]);
  const domainRows = Array.isArray(domains) ? domains : [];
  const scriptRows = Array.isArray(scripts) ? scripts : [];
  const remoteScripts = new Set(scriptRows.map(item => String(item.id || item.name || '')));
  const localWorkers = (await CloudflareFrontendModel.listWorkers()).filter(item => item.account_profile_id === id);
  const differences = [];
  for (const worker of localWorkers) {
    const domain = domainRows.find(item => String(item.hostname || '').toLowerCase() === String(worker.hostname || '').toLowerCase());
    if (!remoteScripts.has(worker.worker_name)) differences.push({ workerId: worker.id, type: 'remote_worker_missing', workerName: worker.worker_name });
    if (worker.hostname && !domain) differences.push({ workerId: worker.id, type: 'remote_domain_missing', hostname: worker.hostname });
    if (domain?.id && domain.id !== worker.cloudflare_domain_id) {
      await CloudflareFrontendModel.updateWorker(worker.id, { domainId: domain.id });
    }
  }
  await CloudflareFrontendModel.updateAccountVerification(id, {
    status: 'valid', tokenFingerprint: tokenFingerprint(profile.apiToken), activeZones
  });
  return { id, activeZones, localWorkerCount: localWorkers.length, remoteWorkerCount: remoteScripts.size, differences };
}

async function prepareMigration(input = {}) {
  const hostname = normalizeHostname(input.hostname);
  const source = await CloudflareFrontendModel.getWorkerByHostname(hostname);
  if (!source) throw new Error('没有找到需要迁移的前台域名记录');
  const targetProfileId = String(input.targetAccountProfileId || '').trim();
  if (!targetProfileId || targetProfileId === source.account_profile_id) throw new Error('请选择不同的目标 Cloudflare 账号');
  const targetProfile = findProfile(targetProfileId);
  const targetAccount = await CloudflareFrontendModel.getAccount(targetProfileId);
  if (!targetAccount || !targetAccount.allocation_enabled) throw new Error('目标账号不存在或已停止分配');
  const created = await CloudflareFrontendModel.createMigration({
    hostname, sourceAccountProfileId: source.account_profile_id, targetAccountProfileId: targetProfileId,
    sourceWorkerId: source.id, migrationType: 'same_domain', keepOldResources: true
  });
  let targetWorker;
  try {
    targetWorker = await CloudflareFrontendModel.reserveWorker(targetProfileId, null, null, {
      previousWorkerId: source.id, migrationState: 'prepared'
    });
    await withProvisioningLock(() => provisionReservedWorker(targetProfile, targetWorker));
    await CloudflareFrontendModel.updateWorker(targetWorker.id, { state: 'ready', deployed: true, migrationState: 'prepared' });
    await CloudflareFrontendModel.updateMigration(created.id, 'prepared', { targetWorkerId: targetWorker.id });
    return { migrationId: created.id, hostname, targetWorkerId: targetWorker.id, targetWorkerName: targetWorker.workerName, state: 'prepared' };
  } catch (error) {
    await CloudflareFrontendModel.updateMigration(created.id, 'failed', { targetWorkerId: targetWorker?.id, error: error.message });
    throw error;
  }
}

async function cutoverMigration(id) {
  const migration = await CloudflareFrontendModel.getMigration(id);
  if (!migration || migration.state !== 'prepared') throw new Error('迁移任务不存在或当前状态不能切换');
  const target = await CloudflareFrontendModel.getWorker(migration.target_worker_id);
  const profile = findProfile(migration.target_account_profile_id);
  const zones = await listActiveZones(profile);
  const zone = zones.filter(item => migration.hostname === item || migration.hostname.endsWith(`.${item}`)).sort((a, b) => b.length - a.length)[0];
  if (!zone) throw new Error('目标账号中的对应 Zone 尚未 Active；请先完成 Nameserver 切换');
  let domain;
  try {
    domain = await request(profile, 'PUT', `/accounts/${encodeURIComponent(profile.accountId)}/workers/domains`, {
      body: JSON.stringify({ hostname: migration.hostname, service: target.worker_name, zone_name: zone }),
      headers: { 'Content-Type': 'application/json' }
    });
    await CloudflareFrontendModel.promoteMigratedWorker(migration.source_worker_id, target.id, migration.hostname, domain.id);
    await CloudflareFrontendModel.updateMigration(id, 'cutover', { targetWorkerId: target.id });
    const health = await checkHealth(migration.hostname);
    await CloudflareFrontendModel.updateWorker(target.id, { state: health.healthy ? 'ready' : 'failed', health });
    return { id, hostname: migration.hostname, state: 'cutover', health };
  } catch (error) {
    await CloudflareFrontendModel.updateMigration(id, 'prepared', { error: error.message });
    throw error;
  }
}

async function rollbackMigration(id) {
  const migration = await CloudflareFrontendModel.getMigration(id);
  if (!migration) throw new Error('迁移任务不存在');
  if (migration.state === 'cutover' || migration.state === 'completed') throw new Error('域名已经切换，涉及 Nameserver，不能自动回滚');
  if (migration.target_worker_id) {
    const target = await CloudflareFrontendModel.getWorker(migration.target_worker_id);
    const profile = findProfile(migration.target_account_profile_id);
    if (target) await request(profile, 'DELETE', `/accounts/${encodeURIComponent(profile.accountId)}/workers/scripts/${encodeURIComponent(target.worker_name)}`).catch(() => undefined);
    await CloudflareFrontendModel.updateWorker(migration.target_worker_id, { state: 'failed', migrationState: 'rolled_back', errorMessage: '迁移已由管理员回滚' });
  }
  await CloudflareFrontendModel.updateMigration(id, 'rolled_back');
  return { id, state: 'rolled_back' };
}

async function completeMigration(id) {
  const migration = await CloudflareFrontendModel.getMigration(id);
  if (!migration || migration.state !== 'cutover') throw new Error('迁移尚未完成正式切换');
  await CloudflareFrontendModel.updateMigration(id, 'completed');
  await CloudflareFrontendModel.updateWorker(migration.target_worker_id, { migrationState: 'none' });
  return { id, state: 'completed', oldResourcesKept: true };
}

async function deleteRemoteWorker(id) {
  const worker = await CloudflareFrontendModel.getWorker(id);
  if (!worker) throw new Error('前台 Worker 不存在');
  const profile = findProfile(worker.account_profile_id);
  let domainId = worker.cloudflare_domain_id;
  if (!domainId && worker.hostname) {
    const domains = await request(profile, 'GET', `/accounts/${encodeURIComponent(profile.accountId)}/workers/domains`);
    domainId = (Array.isArray(domains) ? domains : []).find(item => String(item.hostname || '').toLowerCase() === worker.hostname.toLowerCase())?.id;
  }
  if (domainId) await request(profile, 'DELETE', `/accounts/${encodeURIComponent(profile.accountId)}/workers/domains/${encodeURIComponent(domainId)}`);
  await request(profile, 'DELETE', `/accounts/${encodeURIComponent(profile.accountId)}/workers/scripts/${encodeURIComponent(worker.worker_name)}`);
  await CloudflareFrontendModel.updateWorker(id, {
    state: 'failed', migrationState: 'remote_deleted', domainId: null,
    errorMessage: '远端 Worker 已由管理员明确删除'
  });
  return { id, hostname: worker.hostname, workerName: worker.worker_name, remoteDeleted: true };
}

module.exports = {
  listProfiles,
  adoptStoredProfiles,
  saveProfile,
  createDedicatedFrontend,
  finalizeDedicatedFrontend,
  rollbackDedicatedFrontend,
  checkHealth,
  verifyAccount,
  setAccountAllocation,
  updateAccountToken,
  healthCheckWorker,
  redeployWorker,
  reconcileAccount,
  prepareMigration,
  cutoverMigration,
  rollbackMigration,
  completeMigration,
  deleteRemoteWorker,
  tokenFingerprint,
  normalizeProfile,
  normalizeHostname,
  resolveProfileForHostname
};
