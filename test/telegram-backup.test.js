'use strict';

const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const test = require('node:test');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const zlib = require('zlib');
const sqlite3 = require('sqlite3').verbose();
const BackupService = require('../src/services/TelegramBackupService');

const execFileAsync = promisify(execFile);

async function createSQLiteDatabase(file) {
  await new Promise((resolve, reject) => {
    const database = new sqlite3.Database(file, error => {
      if (error) return reject(error);
      database.exec('CREATE TABLE backup_probe (id INTEGER PRIMARY KEY, value TEXT); INSERT INTO backup_probe(value) VALUES (\'ok\');', execError => {
        database.close(closeError => execError || closeError ? reject(execError || closeError) : resolve());
      });
    });
  });
}

test('加密备份可以无限分片并使用完成摘要中的密钥恢复', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-backup-'));
  try {
    const source = path.join(directory, 'source.db');
    const original = crypto.randomBytes(430 * 1024);
    await fs.writeFile(source, original);
    const result = await BackupService.createEncryptedArtifacts(source, {
      backupId: 'webring-test', outputDirectory: directory, partSizeMiB: 0.1
    });
    assert.ok(result.parts.length > 3, '分片不应被固定为最多 3 个');
    const combined = Buffer.concat(await Promise.all(result.parts.map(part => fs.readFile(part.file))));
    assert.equal(crypto.createHash('sha256').update(combined).digest('hex'), result.manifest.encryptedSha256);
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm', Buffer.from(result.keyBase64, 'base64'), Buffer.from(result.manifest.ivBase64, 'base64')
    );
    decipher.setAuthTag(Buffer.from(result.manifest.authTagBase64, 'base64'));
    const compressed = Buffer.concat([decipher.update(combined), decipher.final()]);
    assert.deepEqual(zlib.gunzipSync(compressed), original);
    assert.equal(Object.hasOwn(result.manifest, 'keyBase64'), false, '恢复清单不能重复保存解密密钥');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('手动后台备份使用统一 DB_PATH 并持续写入可公开状态', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-runtime-backup-'));
  try {
    const source = path.join(directory, 'runtime', 'navigation.sqlite');
    const configFile = path.join(directory, 'telegram-backup.json');
    await fs.mkdir(path.dirname(source), { recursive: true });
    await createSQLiteDatabase(source);
    await fs.writeFile(configFile, JSON.stringify({
      enabled: true,
      botToken: 'test-token',
      chatId: '-1000000000000',
      partSizeMiB: 18
    }));

    const servicePath = path.resolve(__dirname, '..', 'src', 'services', 'TelegramBackupService.js');
    const script = `
      global.fetch = async () => {
        await new Promise(resolve => setTimeout(resolve, 30));
        global.__messageId = (global.__messageId || 0) + 1;
        return { ok: true, status: 200, json: async () => ({ ok: true, result: { message_id: global.__messageId } }) };
      };
      const service = require(${JSON.stringify(servicePath)});
      (async () => {
        const started = await service.startBackup();
        const completed = await service.createAndUploadBackup();
        const status = await service.getStatus();
        process.stdout.write(JSON.stringify({
          started, completed, status,
          databasePath: service.DATABASE_PATH,
          backupDirectory: service.BACKUP_DIR
        }));
      })().catch(error => { console.error(error); process.exit(1); });
    `;
    const { stdout } = await execFileAsync(process.execPath, ['-e', script], {
      env: {
        ...process.env,
        DB_PATH: source,
        TELEGRAM_BACKUP_CONFIG_FILE: configFile
      }
    });
    const result = JSON.parse(stdout);
    assert.equal(result.started.started, true);
    assert.equal(result.completed.status, 'completed');
    assert.equal(result.status.latest.status, 'completed');
    assert.equal(result.status.latest.integrity, 'ok');
    assert.equal(result.status.latest.source.name, 'navigation.sqlite');
    assert.equal(result.status.latest.source.configuredBy, 'DB_PATH');
    assert.equal(result.databasePath, path.resolve(source));
    assert.equal(result.backupDirectory, path.join(path.dirname(source), 'backups', 'webring'));
    assert.equal(Object.hasOwn(result.status.latest, 'keyBase64'), false, '状态接口不能泄露解密密钥');
    assert.equal(result.status.latest.parts.some(part => Object.hasOwn(part, 'file')), false, '状态接口不能泄露服务器文件路径');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('DB_PATH 不存在时拒绝创建空数据库并记录失败阶段', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-missing-backup-'));
  try {
    const source = path.join(directory, 'missing', 'webring.db');
    const configFile = path.join(directory, 'telegram-backup.json');
    const backupDirectory = path.join(directory, 'artifacts');
    await fs.writeFile(configFile, JSON.stringify({
      enabled: true,
      botToken: 'test-token',
      chatId: '-1000000000000',
      partSizeMiB: 18
    }));
    const servicePath = path.resolve(__dirname, '..', 'src', 'services', 'TelegramBackupService.js');
    const script = `
      const service = require(${JSON.stringify(servicePath)});
      (async () => {
        let message = '';
        try { await service.createAndUploadBackup(); } catch (error) { message = error.message; }
        const status = await service.getStatus();
        process.stdout.write(JSON.stringify({ message, status }));
      })().catch(error => { console.error(error); process.exit(1); });
    `;
    const { stdout } = await execFileAsync(process.execPath, ['-e', script], {
      env: {
        ...process.env,
        DB_PATH: source,
        TELEGRAM_BACKUP_CONFIG_FILE: configFile,
        TELEGRAM_BACKUP_DIRECTORY: backupDirectory
      }
    });
    const result = JSON.parse(stdout);
    assert.equal(result.message, '运行时数据库不存在或不可读取');
    assert.equal(result.status.latest.status, 'failed');
    assert.equal(result.status.latest.stage, 'source_validation');
    await assert.rejects(fs.stat(source), error => error.code === 'ENOENT');
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
