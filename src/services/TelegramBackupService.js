'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const zlib = require('zlib');
const { pipeline } = require('stream/promises');
const sqlite3 = require('sqlite3').verbose();
const { DATABASE_PATH } = require('../config/databasePath');

const APP_ROOT = path.resolve(__dirname, '..', '..');
const CONFIG_FILE = path.resolve(process.env.TELEGRAM_BACKUP_CONFIG_FILE || path.join(APP_ROOT, 'data', 'telegram-backup.json'));
const BACKUP_DIR = path.resolve(process.env.TELEGRAM_BACKUP_DIRECTORY
  || path.join(path.dirname(DATABASE_PATH), 'backups', 'webring'));
const STATUS_FILE = path.join(BACKUP_DIR, '.telegram-backup-status.json');
const DEFAULT_PART_SIZE_MIB = 18;
const RETENTION_DAYS = 14;
let activeBackup = null;
let activeBackupId = '';

function timestamp(date = new Date()) {
  return new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  }).format(date).replace(/[-: ]/g, '');
}

async function writeJsonAtomic(file, value, mode = 0o600) {
  await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.tmp`;
  await fsp.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode });
  await fsp.chmod(temporary, mode);
  await fsp.rename(temporary, file);
}

async function readJson(file, fallback = null) {
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

function publicBackupState(state) {
  if (!state) return null;
  const result = { ...state };
  delete result.keyBase64;
  delete result.encryptedFile;
  delete result.manifestFile;
  if (Array.isArray(result.parts)) {
    result.parts = result.parts.map(part => {
      const safePart = { ...part };
      delete safePart.file;
      return safePart;
    });
  }
  return result;
}

async function writePublicStatus(state) {
  await writeJsonAtomic(STATUS_FILE, publicBackupState(state));
}

async function validateDatabaseSource(source = DATABASE_PATH) {
  let stat;
  try {
    await fsp.access(source, fs.constants.R_OK);
    stat = await fsp.stat(source);
  } catch (error) {
    const failure = new Error('运行时数据库不存在或不可读取');
    failure.code = 'BACKUP_SOURCE_UNAVAILABLE';
    failure.cause = error;
    throw failure;
  }
  if (!stat.isFile()) {
    const failure = new Error('运行时数据库路径不是有效文件');
    failure.code = 'BACKUP_SOURCE_INVALID';
    throw failure;
  }
  return stat;
}

function normalizeConfig(input = {}, current = {}) {
  const token = String(input.botToken || '').trim() || String(current.botToken || '').trim();
  const chatId = String(input.chatId ?? current.chatId ?? '').trim();
  const enabled = input.enabled === undefined ? Boolean(current.enabled) : Boolean(input.enabled);
  const requestedPartSize = Number(input.partSizeMiB ?? current.partSizeMiB ?? DEFAULT_PART_SIZE_MIB);
  const partSizeMiB = Math.min(18, Math.max(1, Number.isFinite(requestedPartSize) ? Math.floor(requestedPartSize) : DEFAULT_PART_SIZE_MIB));
  if (enabled && (!token || !chatId)) throw new Error('启用 Telegram 备份前必须填写独立 Bot Token 和 Chat ID');
  return { enabled, botToken: token, chatId, partSizeMiB };
}

async function loadConfig() {
  return normalizeConfig(await readJson(CONFIG_FILE, {}));
}

async function saveConfig(input) {
  const current = await loadConfig();
  const next = normalizeConfig(input, current);
  if (input.clearToken === true) next.botToken = '';
  if (next.enabled && !next.botToken) throw new Error('启用 Telegram 备份前必须填写独立 Bot Token');
  await writeJsonAtomic(CONFIG_FILE, next);
  return publicConfig(next);
}

function publicConfig(config) {
  return {
    enabled: Boolean(config.enabled),
    botTokenConfigured: Boolean(config.botToken),
    chatId: config.chatId || '',
    partSizeMiB: Number(config.partSizeMiB || DEFAULT_PART_SIZE_MIB),
    unlimitedParts: true,
    privateKeyDelivery: 'completion_summary'
  };
}

async function sha256File(file) {
  const hash = crypto.createHash('sha256');
  await pipeline(fs.createReadStream(file), hash);
  return hash.digest('hex');
}

async function sqliteBackup(source, destination) {
  await fsp.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  await new Promise((resolve, reject) => {
    const database = new sqlite3.Database(source, sqlite3.OPEN_READONLY, error => {
      if (error) return reject(error);
      const backup = database.backup(destination);
      backup.step(-1, stepError => {
        backup.finish(finishError => database.close(closeError => {
          const failure = stepError || finishError || closeError;
          if (failure) reject(failure); else resolve();
        }));
      });
    });
  });
}

async function integrityCheck(file) {
  return new Promise((resolve, reject) => {
    const database = new sqlite3.Database(file, sqlite3.OPEN_READONLY, error => {
      if (error) return reject(error);
      database.get('PRAGMA integrity_check', (queryError, row) => {
        database.close();
        if (queryError) reject(queryError);
        else if (row?.integrity_check !== 'ok') reject(new Error('SQLite integrity_check 未通过'));
        else resolve('ok');
      });
    });
  });
}

async function splitFile(file, partSizeBytes, backupId) {
  const stat = await fsp.stat(file);
  if (stat.size <= partSizeBytes) return [{ number: 1, file, bytes: stat.size, sha256: await sha256File(file) }];
  const handle = await fsp.open(file, 'r');
  const parts = [];
  try {
    let offset = 0;
    let number = 1;
    while (offset < stat.size) {
      const length = Math.min(partSizeBytes, stat.size - offset);
      const buffer = Buffer.allocUnsafe(length);
      const { bytesRead } = await handle.read(buffer, 0, length, offset);
      const partFile = path.join(path.dirname(file), `${backupId}.db.gz.aes.part${String(number).padStart(4, '0')}`);
      await fsp.writeFile(partFile, buffer.subarray(0, bytesRead), { mode: 0o600 });
      parts.push({ number, file: partFile, bytes: bytesRead, sha256: await sha256File(partFile) });
      offset += bytesRead;
      number += 1;
    }
  } finally {
    await handle.close();
  }
  return parts;
}

async function createEncryptedArtifacts(sourceFile, options = {}) {
  const backupId = options.backupId || `webring-${timestamp()}`;
  const partSizeMiB = Number(options.partSizeMiB || DEFAULT_PART_SIZE_MIB);
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const encryptedFile = path.join(options.outputDirectory || path.dirname(sourceFile), `${backupId}.db.gz.aes`);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  await pipeline(fs.createReadStream(sourceFile), zlib.createGzip({ level: 9 }), cipher, fs.createWriteStream(encryptedFile, { mode: 0o600 }));
  const authTag = cipher.getAuthTag();
  const encryptedStat = await fsp.stat(encryptedFile);
  const parts = await splitFile(encryptedFile, Math.max(1, Math.floor(partSizeMiB * 1024 * 1024)), backupId);
  const manifest = {
    version: 1,
    backupId,
    createdAt: new Date().toISOString(),
    algorithm: 'aes-256-gcm',
    compression: 'gzip',
    ivBase64: iv.toString('base64'),
    authTagBase64: authTag.toString('base64'),
    encryptedBytes: encryptedStat.size,
    encryptedSha256: await sha256File(encryptedFile),
    partSizeMiB,
    partCount: parts.length,
    parts: parts.map(part => ({ number: part.number, file: path.basename(part.file), bytes: part.bytes, sha256: part.sha256 }))
  };
  const manifestFile = path.join(path.dirname(encryptedFile), `${backupId}.manifest.json`);
  await writeJsonAtomic(manifestFile, manifest);
  return { backupId, keyBase64: key.toString('base64'), encryptedFile, manifestFile, manifest, parts };
}

async function telegramRequest(config, method, bodyFactory, retries = 3) {
  const endpoint = `https://api.telegram.org/bot${config.botToken}/${method}`;
  let lastError;
  for (let attempt = 0; attempt < retries; attempt += 1) {
    try {
      const response = await fetch(endpoint, { method: 'POST', body: bodyFactory() });
      const payload = await response.json();
      if (response.ok && payload.ok) return payload.result;
      const error = new Error(String(payload.description || `Telegram HTTP ${response.status}`));
      error.retryAfter = Number(payload.parameters?.retry_after || 0);
      throw error;
    } catch (error) {
      lastError = error;
      if (attempt + 1 >= retries) break;
      const waitSeconds = Math.max(2 ** attempt, Number(error.retryAfter || 0));
      await new Promise(resolve => setTimeout(resolve, waitSeconds * 1000));
    }
  }
  throw lastError;
}

async function sendMessage(config, text) {
  return telegramRequest(config, 'sendMessage', () => {
    const form = new FormData();
    form.set('chat_id', config.chatId);
    form.set('text', text);
    return form;
  });
}

async function sendDocument(config, file, caption) {
  const buffer = await fsp.readFile(file);
  return telegramRequest(config, 'sendDocument', () => {
    const form = new FormData();
    form.set('chat_id', config.chatId);
    form.set('caption', caption);
    form.set('document', new Blob([buffer]), path.basename(file));
    return form;
  });
}

function pendingFile(backupId) {
  return path.join(BACKUP_DIR, `.${backupId}.pending.json`);
}

async function uploadArtifacts(config, state) {
  state.status = 'uploading';
  state.stage = 'uploading_parts';
  await writePublicStatus(state);
  await writeJsonAtomic(pendingFile(state.backupId), state);
  for (const part of state.parts) {
    if (state.uploadedParts.includes(part.number)) continue;
    const message = await sendDocument(config, part.file, `${state.backupId} · 分片 ${part.number}/${state.parts.length}\nSHA-256: ${part.sha256}`);
    state.uploadedParts.push(part.number);
    state.messageIds.push(Number(message.message_id));
    await writeJsonAtomic(pendingFile(state.backupId), state);
    await writePublicStatus(state);
  }
  if (!state.manifestMessageId) {
    state.stage = 'uploading_manifest';
    await writePublicStatus(state);
    const message = await sendDocument(config, state.manifestFile, `${state.backupId} · 恢复清单`);
    state.manifestMessageId = Number(message.message_id);
    await writeJsonAtomic(pendingFile(state.backupId), state);
  }
  const summary = [
    '✅ 导航系统数据库备份完成',
    '',
    `备份编号：${state.backupId}`,
    `完整性：${state.integrity}`,
    `原始大小：${state.originalBytes} 字节`,
    `加密大小：${state.manifest.encryptedBytes} 字节`,
    `分片：${state.parts.length}/${state.parts.length}`,
    `完整 SHA-256：${state.manifest.encryptedSha256}`,
    `解密密钥（Base64）：${state.keyBase64}`,
    `IV（Base64）：${state.manifest.ivBase64}`,
    `认证标签（Base64）：${state.manifest.authTagBase64}`,
    '',
    '警告：本摘要中的密钥可直接解密本批备份，请保护此 Telegram 会话。'
  ].join('\n');
  const completion = await sendMessage(config, summary);
  state.status = 'completed';
  state.stage = 'completed';
  state.completedAt = new Date().toISOString();
  state.completionMessageId = Number(completion.message_id);
  const publicState = publicBackupState(state);
  await writeJsonAtomic(STATUS_FILE, publicState);
  await fsp.unlink(pendingFile(state.backupId)).catch(() => {});
  return publicState;
}

async function prepareAndUpload(sourceFile, {
  removeSourceAfterEncryption = false,
  backupId = '',
  config: suppliedConfig = null,
  source = null
} = {}) {
  const config = suppliedConfig || await loadConfig();
  if (!config.enabled) return { skipped: true, reason: 'Telegram 备份未启用' };
  if (!config.botToken || !config.chatId) throw new Error('Telegram 备份配置不完整');
  await fsp.mkdir(BACKUP_DIR, { recursive: true, mode: 0o700 });
  const preparingState = {
    status: 'running',
    stage: 'integrity_check',
    backupId: backupId || `webring-${timestamp()}`,
    createdAt: new Date().toISOString(),
    source
  };
  await writePublicStatus(preparingState);
  const integrity = await integrityCheck(sourceFile);
  const sourceStat = await fsp.stat(sourceFile);
  preparingState.stage = 'encrypting';
  preparingState.integrity = integrity;
  await writePublicStatus(preparingState);
  const artifacts = await createEncryptedArtifacts(sourceFile, {
    backupId: preparingState.backupId,
    outputDirectory: BACKUP_DIR,
    partSizeMiB: config.partSizeMiB
  });
  const state = {
    status: 'prepared', stage: 'prepared', backupId: artifacts.backupId,
    createdAt: preparingState.createdAt, integrity, source,
    originalBytes: sourceStat.size, keyBase64: artifacts.keyBase64,
    encryptedFile: artifacts.encryptedFile, manifestFile: artifacts.manifestFile,
    manifest: artifacts.manifest, parts: artifacts.parts, uploadedParts: [], messageIds: [], manifestMessageId: null
  };
  await writeJsonAtomic(pendingFile(state.backupId), state);
  await writePublicStatus(state);
  if (removeSourceAfterEncryption) {
    await fsp.unlink(sourceFile).catch(() => {});
    await fsp.unlink(`${sourceFile}.sha256`).catch(() => {});
  }
  try {
    return await uploadArtifacts(config, state);
  } catch (error) {
    state.status = 'partial';
    state.stage = 'upload_failed';
    state.lastError = String(error.message || error).slice(0, 500);
    state.lastAttemptAt = new Date().toISOString();
    await writeJsonAtomic(pendingFile(state.backupId), state);
    await writePublicStatus(state);
    throw error;
  }
}

async function executeBackup(backupId, suppliedConfig = null) {
  const config = suppliedConfig || await loadConfig();
  if (!config.enabled) return { skipped: true, reason: 'Telegram 备份未启用' };
  if (!config.botToken || !config.chatId) throw new Error('Telegram 备份配置不完整');
  await fsp.mkdir(BACKUP_DIR, { recursive: true, mode: 0o700 });
  const state = {
    status: 'running',
    stage: 'source_validation',
    backupId,
    createdAt: new Date().toISOString(),
    source: { name: path.basename(DATABASE_PATH), configuredBy: 'DB_PATH' }
  };
  let target = '';
  try {
    await writePublicStatus(state);
    const sourceStat = await validateDatabaseSource(DATABASE_PATH);
    state.source.bytes = sourceStat.size;
    state.stage = 'snapshot';
    await writePublicStatus(state);
    target = path.join(BACKUP_DIR, `${backupId}.db`);
    await sqliteBackup(DATABASE_PATH, target);
    return await prepareAndUpload(target, {
      removeSourceAfterEncryption: true,
      backupId,
      config,
      source: state.source
    });
  } catch (error) {
    const latest = await readJson(STATUS_FILE, null).catch(() => null);
    const failedState = latest?.backupId === backupId ? { ...state, ...latest } : state;
    if (failedState.status !== 'partial') failedState.status = 'failed';
    failedState.stage = failedState.stage || 'failed';
    failedState.lastError = String(error.message || error).slice(0, 500);
    failedState.lastAttemptAt = new Date().toISOString();
    await writePublicStatus(failedState).catch(() => {});
    if (target) await fsp.unlink(target).catch(() => {});
    throw error;
  }
}

function createAndUploadBackup(options = {}) {
  if (activeBackup) return activeBackup;
  activeBackupId = `webring-${timestamp()}`;
  activeBackup = executeBackup(activeBackupId, options.config || null)
    .finally(() => {
      activeBackup = null;
      activeBackupId = '';
    });
  return activeBackup;
}

async function startBackup() {
  if (activeBackup) return { started: false, running: true, backupId: activeBackupId };
  const config = await loadConfig();
  if (!config.enabled) throw new Error('Telegram 备份未启用');
  if (!config.botToken || !config.chatId) throw new Error('Telegram 备份配置不完整');
  if (activeBackup) return { started: false, running: true, backupId: activeBackupId };
  const task = createAndUploadBackup({ config });
  const backupId = activeBackupId;
  void task.catch(error => console.error('Telegram 数据库备份失败：', error?.stack || error));
  return { started: true, running: true, backupId };
}

async function resumePendingBackups() {
  if (activeBackup) return [{ skipped: true, reason: '新的数据库备份正在执行', backupId: activeBackupId }];
  const config = await loadConfig();
  if (!config.enabled) return [];
  await fsp.mkdir(BACKUP_DIR, { recursive: true, mode: 0o700 });
  const names = (await fsp.readdir(BACKUP_DIR)).filter(name => /^\.webring-\d+\.pending\.json$/.test(name)).sort();
  const results = [];
  for (const name of names) {
    const state = await readJson(path.join(BACKUP_DIR, name));
    try { results.push(await uploadArtifacts(config, state)); }
    catch (error) { results.push({ backupId: state.backupId, status: 'partial', error: String(error.message || error) }); }
  }
  return results;
}

async function testConnection() {
  const config = await loadConfig();
  if (!config.botToken || !config.chatId) throw new Error('请先保存独立备份 Bot Token 和 Chat ID');
  const result = await sendMessage(config, `✅ 导航系统备份 Bot 测试成功\n时间：${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`);
  return { sent: true, messageId: Number(result.message_id) };
}

async function getStatus() {
  const config = await loadConfig();
  let latest = await readJson(STATUS_FILE, null);
  if (!activeBackup && ['running', 'prepared', 'uploading'].includes(latest?.status)) {
    const hasPendingUpload = latest?.backupId
      ? await fsp.access(pendingFile(latest.backupId), fs.constants.R_OK).then(() => true).catch(() => false)
      : false;
    latest = {
      ...latest,
      status: hasPendingUpload ? 'partial' : 'failed',
      stage: 'interrupted',
      lastError: hasPendingUpload
        ? '备份任务因服务重启中断，等待失败分片自动重试'
        : '备份任务因服务重启中断，请重新发起备份',
      lastAttemptAt: new Date().toISOString()
    };
    await writePublicStatus(latest);
  }
  return {
    config: publicConfig(config),
    running: Boolean(activeBackup),
    activeBackupId: activeBackupId || null,
    latest
  };
}

module.exports = {
  BACKUP_DIR,
  CONFIG_FILE,
  DATABASE_PATH,
  createAndUploadBackup,
  createEncryptedArtifacts,
  getStatus,
  integrityCheck,
  loadConfig,
  prepareAndUpload,
  resumePendingBackups,
  saveConfig,
  startBackup,
  testConnection,
  validateDatabaseSource
};
