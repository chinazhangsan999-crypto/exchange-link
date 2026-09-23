'use strict';

const crypto = require('crypto');
const zlib = require('zlib');
const StorageService = require('./StorageService');

const TELEGRAM_TIMEOUT_MS = 60_000;
const CHANGE_DEBOUNCE_MS = 60_000;
const TICK_INTERVAL_MS = 15 * 60_000;
const MAX_PART_MIB = 18;

let timer = null;
let changeTimer = null;
let running = false;

function beijingParts(date = new Date()) {
  return Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
  }).formatToParts(date).filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
}

function backupId(date = new Date()) {
  const p = beijingParts(date);
  return `rules-${p.year}${p.month}${p.day}-${p.hour}${p.minute}${p.second}-${crypto.randomBytes(3).toString('hex')}`;
}

function summarizeRules(rules) {
  return {
    ruleCount: rules.length,
    enabledCount: rules.filter(rule => rule.enabled).length,
    disabledCount: rules.filter(rule => !rule.enabled).length,
    globalCount: rules.filter(rule => rule.scope === 'all').length,
    siteSpecificCount: rules.filter(rule => rule.scope !== 'all').length
  };
}

function summarizeUnifiedRules(data = {}) {
  const signalSummary = summarizeRules(data.signalRules || []);
  return {
    ...signalSummary,
    allowCount: (data.allowlist || []).length,
    blockCount: (data.blocklist || []).length,
    policyCount: (data.policies || []).length,
    revisionCount: (data.revisions || []).length,
    totalManagedItems: signalSummary.ruleCount + (data.allowlist || []).length + (data.blocklist || []).length
  };
}

function createSnapshot(data, generatedAt = new Date()) {
  const normalized = Array.isArray(data) ? { signalRules: data, allowlist: [], blocklist: [], policies: [], revisions: [] } : (data || {});
  const sortById = items => [...(items || [])].sort((a, b) => Number(a.id) - Number(b.id));
  const content = {
    signalRules: sortById(normalized.signalRules),
    allowlist: sortById(normalized.allowlist),
    blocklist: sortById(normalized.blocklist),
    policies: sortById(normalized.policies),
    revisions: sortById(normalized.revisions)
  };
  return {
    schemaVersion: 2,
    kind: 'bot-risk-center-unified-rules',
    generatedAt: generatedAt.toISOString(),
    summary: summarizeUnifiedRules(content),
    ...content
  };
}

function encryptSnapshot(snapshot, key = crypto.randomBytes(32)) {
  const plain = Buffer.from(JSON.stringify(snapshot, null, 2), 'utf8');
  const contentSha256 = crypto.createHash('sha256').update(plain).digest('hex');
  const compressed = zlib.gzipSync(plain, { level: 9 });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const header = Buffer.from(`${JSON.stringify({
    format: 'risk-rule-backup-v1', compression: 'gzip', encryption: 'aes-256-gcm',
    iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), contentSha256
  })}\n`, 'utf8');
  return { payload: Buffer.concat([header, ciphertext]), key: key.toString('base64url'), contentSha256 };
}

function splitPayload(payload, partSizeMiB) {
  const bytes = Math.max(1, Math.min(MAX_PART_MIB, Number(partSizeMiB) || MAX_PART_MIB)) * 1024 * 1024;
  const parts = [];
  for (let offset = 0; offset < payload.length; offset += bytes) parts.push(payload.subarray(offset, offset + bytes));
  return parts.length ? parts : [Buffer.alloc(0)];
}

async function telegramRequest(token, method, body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TELEGRAM_TIMEOUT_MS);
  timeout.unref?.();
  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
      method: 'POST', body, signal: controller.signal
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.ok) throw new Error(data.description || `Telegram HTTP ${response.status}`);
    return data.result;
  } finally { clearTimeout(timeout); }
}

async function sendDocument(settings, name, content, caption) {
  const form = new FormData();
  form.set('chat_id', settings.telegramChatId);
  form.set('caption', caption.slice(0, 1000));
  form.set('document', new Blob([content], { type: 'application/octet-stream' }), name);
  return telegramRequest(settings.telegramToken, 'sendDocument', form);
}

async function sendText(settings, text) {
  const form = new URLSearchParams();
  form.set('chat_id', settings.telegramChatId);
  form.set('text', text.slice(0, 4000));
  return telegramRequest(settings.telegramToken, 'sendMessage', form);
}

function completionText(run) {
  return [
    '✅ 风险中心人工规则备份完成',
    `备份编号：${run.backupId}`,
    `规则：${run.summary.ruleCount}（启用 ${run.summary.enabledCount} / 停用 ${run.summary.disabledCount}）`,
    `名单：允许 ${run.summary.allowCount || 0} / 阻止 ${run.summary.blockCount || 0}`,
    `策略与历史：策略 ${run.summary.policyCount || 0} / 修订 ${run.summary.revisionCount || 0}`,
    `范围：全站 ${run.summary.globalCount} / 单站 ${run.summary.siteSpecificCount}`,
    `分片：${run.partsTotal}`,
    `SHA-256：${run.contentSha256}`,
    `解密密钥：${run.backupKey}`,
    '算法：AES-256-GCM；解密后再使用 gzip 解压。请将本摘要与备份分片一起保存。'
  ].join('\n');
}

async function uploadRun(settings, run) {
  const parts = splitPayload(run.encryptedPayload, settings.partSizeMiB);
  const uploaded = new Set(run.uploadedParts || []);
  for (let index = 0; index < parts.length; index += 1) {
    const number = index + 1;
    if (uploaded.has(number)) continue;
    const suffix = String(number).padStart(3, '0');
    await sendDocument(settings, `${run.backupId}.part${suffix}.bin`, parts[index],
      `人工规则加密备份 ${run.backupId} · 分片 ${number}/${parts.length}`);
    await StorageService.markRuleBackupPartUploaded(run.id, number);
  }
  if (!run.summarySent) await sendText(settings, completionText({ ...run, partsTotal: parts.length }));
  await StorageService.finishRuleBackupRun(run.id, { contentSha256: run.contentSha256, summarySent: true });
  return { backupId: run.backupId, partsTotal: parts.length, ...run.summary, contentSha256: run.contentSha256 };
}

function assertConfigured(settings, force) {
  if (!settings?.telegramConfigured || !settings.telegramToken || !settings.telegramChatId) {
    throw Object.assign(new Error('请先配置独立的人工规则 Backup Bot Token 和 Chat ID'), { statusCode: 400 });
  }
  if (!settings.enabled && !force) throw Object.assign(new Error('人工规则自动备份尚未启用'), { statusCode: 400 });
}

async function runBackup({ triggerType = 'manual', createdBy = 'system', force = false } = {}) {
  if (running) throw Object.assign(new Error('人工规则备份正在执行'), { statusCode: 409 });
  running = true;
  let runId = null;
  try {
    const settings = await StorageService.getRuleBackupSettings({ includeSecrets: true });
    assertConfigured(settings, force);
    const data = await StorageService.getUnifiedRuleBackupData();
    const snapshot = createSnapshot(data);
    const encrypted = encryptSnapshot(snapshot);
    const id = backupId();
    const parts = splitPayload(encrypted.payload, settings.partSizeMiB);
    const created = await StorageService.createRuleBackupRun({
      backupId: id, triggerType, summary: snapshot.summary, contentSha256: encrypted.contentSha256,
      partsTotal: parts.length, encryptedPayload: encrypted.payload, backupKey: encrypted.key, createdBy
    });
    runId = created.id;
    return await uploadRun(settings, {
      id: runId, backupId: id, summary: snapshot.summary, contentSha256: encrypted.contentSha256,
      encryptedPayload: encrypted.payload, backupKey: encrypted.key, partsTotal: parts.length,
      uploadedParts: [], summarySent: false
    });
  } catch (error) {
    if (runId) await StorageService.failRuleBackupRun(runId, error.message).catch(() => {});
    throw error;
  } finally { running = false; }
}

async function retryFailed() {
  if (running) throw Object.assign(new Error('人工规则备份正在执行'), { statusCode: 409 });
  running = true;
  let run = null;
  try {
    const settings = await StorageService.getRuleBackupSettings({ includeSecrets: true });
    assertConfigured(settings, true);
    run = await StorageService.getRuleBackupRunForRetry();
    if (!run) throw Object.assign(new Error('没有可重试的失败备份'), { statusCode: 404 });
    if (!run.backupKey) throw new Error('失败备份的解密密钥不可用');
    return await uploadRun(settings, run);
  } catch (error) {
    if (run?.id) await StorageService.failRuleBackupRun(run.id, error.message).catch(() => {});
    throw error;
  } finally { running = false; }
}

async function testConnection() {
  const settings = await StorageService.getRuleBackupSettings({ includeSecrets: true });
  assertConfigured(settings, true);
  const bot = await telegramRequest(settings.telegramToken, 'getMe', new URLSearchParams());
  await sendText(settings, '✅ 风险中心人工规则 Backup Bot 连接测试成功。此机器人仅用于规则备份，不用于风险告警。');
  return { username: bot.username || '', chatId: settings.telegramChatId };
}

async function status() {
  const [settings, runs] = await Promise.all([
    StorageService.getRuleBackupSettings(), StorageService.listRuleBackupRuns(20)
  ]);
  return { settings, running, runs };
}

function scheduleChangedBackup() {
  if (changeTimer) clearTimeout(changeTimer);
  changeTimer = setTimeout(async () => {
    changeTimer = null;
    const settings = await StorageService.getRuleBackupSettings().catch(() => null);
    if (!settings?.enabled || !settings.automaticOnChange) return;
    await runBackup({ triggerType: 'rule_change' }).catch(error => console.error('人工规则变更备份失败：', error.message));
  }, CHANGE_DEBOUNCE_MS);
  changeTimer.unref?.();
}

async function tick() {
  if (running) return;
  const settings = await StorageService.getRuleBackupSettings().catch(() => null);
  if (!settings?.enabled || !settings.telegramConfigured) return;
  const failed = (await StorageService.listRuleBackupRuns(1).catch(() => []))[0];
  if (failed?.status === 'failed' && (!failed.nextRetryAt || new Date(failed.nextRetryAt) <= new Date())) {
    await retryFailed().catch(error => console.error('人工规则备份重试失败：', error.message));
    return;
  }
  const now = new Date();
  const parts = beijingParts(now);
  if (Number(parts.hour) !== settings.backupHourBjt) return;
  if (settings.lastBackupAt) {
    const last = beijingParts(new Date(settings.lastBackupAt));
    if (`${last.year}-${last.month}-${last.day}` === `${parts.year}-${parts.month}-${parts.day}`) return;
  }
  await runBackup({ triggerType: 'scheduled' }).catch(error => console.error('人工规则定时备份失败：', error.message));
}

function start() {
  if (timer) return;
  timer = setInterval(() => { void tick(); }, TICK_INTERVAL_MS);
  timer.unref?.();
  setTimeout(() => { void tick(); }, 30_000).unref?.();
}

function stop() {
  if (timer) clearInterval(timer);
  if (changeTimer) clearTimeout(changeTimer);
  timer = null;
  changeTimer = null;
}

module.exports = {
  start, stop, runBackup, retryFailed, testConnection, status, scheduleChangedBackup,
  createSnapshot, summarizeRules, summarizeUnifiedRules, encryptSnapshot, splitPayload, completionText
};
