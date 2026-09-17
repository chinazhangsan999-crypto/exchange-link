'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { promisify } = require('node:util');
const { execFile } = require('node:child_process');

const execFileAsync = promisify(execFile);
const PROJECT_ROOT = path.join(__dirname, '..', '..');
const STATE_FILE = String(process.env.CLOUDFLARE_IP_WHITELIST_STATE_FILE
  || path.join(PROJECT_ROOT, 'data', 'cloudflare-ip-whitelist-state.json')).trim();
const FALLBACK_FRAGMENT_FILE = path.join(PROJECT_ROOT, 'ops', 'cloudflare-ips.caddy');
const OFFICIAL_URLS = Object.freeze({
  ipv4: 'https://www.cloudflare.com/ips-v4',
  ipv6: 'https://www.cloudflare.com/ips-v6'
});
const OFFICIAL_CACHE_TTL_MS = 5 * 60 * 1000;
const FETCH_TIMEOUT_MS = 8000;
const SYSTEMD_UNIT = 'webring-cloudflare-ip-sync.service';
let officialCache = { expiresAt: 0, value: null };

function normalizeCidr(value, expectedFamily) {
  const cidr = String(value || '').trim();
  const separator = cidr.lastIndexOf('/');
  if (separator <= 0) throw new Error(`Cloudflare IP 网段格式不合法：${cidr || '(空值)'}`);
  const address = cidr.slice(0, separator);
  const prefix = Number(cidr.slice(separator + 1));
  const family = net.isIP(address);
  const maxPrefix = family === 4 ? 32 : family === 6 ? 128 : 0;
  if (family !== expectedFamily || !Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    throw new Error(`Cloudflare IPv${expectedFamily} 网段格式不合法：${cidr}`);
  }
  return `${address.toLowerCase()}/${prefix}`;
}

function parseOfficialList(text, family) {
  const values = String(text || '')
    .split(/\r?\n/)
    .map(item => item.trim())
    .filter(Boolean)
    .map(item => normalizeCidr(item, family));
  const unique = [...new Set(values)];
  const minimum = family === 4 ? 10 : 5;
  if (unique.length < minimum) {
    throw new Error(`Cloudflare 官方 IPv${family} 清单数量异常（仅 ${unique.length} 条）`);
  }
  return unique;
}

function parseCaddyFragment(text) {
  const tokens = String(text || '')
    .replace(/#[^\r\n]*/g, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .filter(token => token !== '@cloudflare' && token !== 'remote_ip');
  const ipv4 = [];
  const ipv6 = [];
  for (const token of tokens) {
    const address = token.slice(0, token.lastIndexOf('/'));
    const family = net.isIP(address);
    if (family === 4) ipv4.push(normalizeCidr(token, 4));
    if (family === 6) ipv6.push(normalizeCidr(token, 6));
  }
  return { ipv4: [...new Set(ipv4)], ipv6: [...new Set(ipv6)] };
}

async function fetchText(url, fetchImpl = global.fetch) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('Cloudflare 官方清单请求超时')), FETCH_TIMEOUT_MS);
  try {
    const response = await fetchImpl(url, {
      signal: controller.signal,
      cache: 'no-store',
      headers: { Accept: 'text/plain', 'User-Agent': 'webring-cloudflare-ip-audit/1.0' }
    });
    if (!response.ok) throw new Error(`Cloudflare 官方清单返回 HTTP ${response.status}`);
    return response.text();
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchOfficialLists({ force = false, fetchImpl = global.fetch } = {}) {
  if (!force && officialCache.value && officialCache.expiresAt > Date.now()) return officialCache.value;
  const [ipv4Text, ipv6Text] = await Promise.all([
    fetchText(OFFICIAL_URLS.ipv4, fetchImpl),
    fetchText(OFFICIAL_URLS.ipv6, fetchImpl)
  ]);
  const value = {
    ipv4: parseOfficialList(ipv4Text, 4),
    ipv6: parseOfficialList(ipv6Text, 6),
    fetchedAt: new Date().toISOString(),
    source: 'cloudflare-live'
  };
  officialCache = { expiresAt: Date.now() + OFFICIAL_CACHE_TTL_MS, value };
  return value;
}

function readJsonFile(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return null; }
}

function readConfiguredLists() {
  const state = readJsonFile(STATE_FILE);
  const configured = state?.configured;
  if (Array.isArray(configured?.ipv4) && Array.isArray(configured?.ipv6)) {
    try {
      return {
        ipv4: configured.ipv4.map(item => normalizeCidr(item, 4)),
        ipv6: configured.ipv6.map(item => normalizeCidr(item, 6)),
        source: 'server-state',
        state
      };
    } catch {
      // 状态文件损坏时只降级到仓库默认片段，绝不能让仪表盘整体报错。
    }
  }
  try {
    return {
      ...parseCaddyFragment(fs.readFileSync(FALLBACK_FRAGMENT_FILE, 'utf8')),
      source: 'repository-fallback',
      state: null
    };
  } catch {
    return { ipv4: [], ipv6: [], source: 'unavailable', state: null };
  }
}

function difference(left, right) {
  const rightSet = new Set(right);
  return left.filter(item => !rightSet.has(item));
}

function compareLists(official, configured) {
  const missing = {
    ipv4: difference(official.ipv4, configured.ipv4),
    ipv6: difference(official.ipv6, configured.ipv6)
  };
  const extra = {
    ipv4: difference(configured.ipv4, official.ipv4),
    ipv6: difference(configured.ipv6, official.ipv6)
  };
  return {
    synchronized: !missing.ipv4.length && !missing.ipv6.length && !extra.ipv4.length && !extra.ipv6.length,
    missing,
    extra
  };
}

async function getStatus({ forceOfficial = false, fetchImpl = global.fetch } = {}) {
  const configured = readConfiguredLists();
  let official;
  let officialError = '';
  try {
    official = await fetchOfficialLists({ force: forceOfficial, fetchImpl });
  } catch (error) {
    officialError = error.message;
    const lastOfficial = configured.state?.official;
    official = Array.isArray(lastOfficial?.ipv4) && Array.isArray(lastOfficial?.ipv6)
      ? { ipv4: lastOfficial.ipv4, ipv6: lastOfficial.ipv6, fetchedAt: configured.state?.checkedAt || null, source: 'last-server-check' }
      : { ipv4: [], ipv6: [], fetchedAt: null, source: 'unavailable' };
  }
  const comparison = official.ipv4.length || official.ipv6.length
    ? compareLists(official, configured)
    : { synchronized: false, missing: { ipv4: [], ipv6: [] }, extra: { ipv4: [], ipv6: [] } };
  return {
    official,
    configured: { ipv4: configured.ipv4, ipv6: configured.ipv6, source: configured.source },
    comparison,
    officialError,
    lastCheckStatus: configured.state?.status || 'not-installed',
    lastCheckedAt: configured.state?.checkedAt || null,
    lastAppliedAt: configured.state?.appliedAt || null,
    lastError: configured.state?.error || '',
    automation: {
      unit: SYSTEMD_UNIT,
      schedule: '每天 04:20，最多随机延迟 30 分钟',
      installed: Boolean(configured.state),
      manualAvailable: process.platform !== 'win32' && Boolean(configured.state)
    }
  };
}

async function triggerSync() {
  if (process.platform === 'win32') {
    const error = new Error('本地 Windows 环境不能启动服务器 systemd 更新任务');
    error.code = 'SYNC_UNAVAILABLE';
    throw error;
  }
  try {
    await execFileAsync('/usr/bin/sudo', ['-n', '/usr/bin/systemctl', 'start', SYSTEMD_UNIT], {
      timeout: 45_000,
      windowsHide: true,
      maxBuffer: 128 * 1024
    });
  } catch (error) {
    const detail = String(error.stderr || error.message || '').trim();
    throw new Error(`启动 Cloudflare IP 白名单更新任务失败：${detail || '请检查 systemd 与 sudoers 配置'}`);
  }
  officialCache = { expiresAt: 0, value: null };
  return getStatus({ forceOfficial: true });
}

module.exports = {
  OFFICIAL_URLS,
  STATE_FILE,
  parseOfficialList,
  parseCaddyFragment,
  compareLists,
  fetchOfficialLists,
  getStatus,
  triggerSync
};
