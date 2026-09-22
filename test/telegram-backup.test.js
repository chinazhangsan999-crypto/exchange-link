'use strict';

const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const test = require('node:test');
const zlib = require('zlib');
const BackupService = require('../src/services/TelegramBackupService');

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
