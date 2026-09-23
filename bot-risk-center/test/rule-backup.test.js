'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const {
  createSnapshot, summarizeRules, encryptSnapshot, splitPayload, completionText
} = require('../src/services/RuleBackupService');

test('融合规则快照包含名单、信号规则、策略和修订历史', () => {
  const signalRules = [
    { id: 2, scope: 'site', siteKey: 'site-a', signal: 'x', enabled: false },
    { id: 1, scope: 'all', siteKey: '*', signal: 'y', enabled: true }
  ];
  const snapshot = createSnapshot({ signalRules, allowlist: [{ id: 3, enabled: true }], blocklist: [{ id: 4, hitCount: 2 }], policies: [{ id: 5 }], revisions: [{ id: 6 }] }, new Date('2026-09-22T00:00:00.000Z'));
  assert.equal(snapshot.kind, 'bot-risk-center-unified-rules');
  assert.deepEqual(snapshot.signalRules.map(rule => rule.id), [1, 2]);
  assert.deepEqual(snapshot.summary, {
    ruleCount: 2, enabledCount: 1, disabledCount: 1, globalCount: 1, siteSpecificCount: 1,
    allowCount: 1, blockCount: 1, policyCount: 1, revisionCount: 1, totalManagedItems: 4
  });
  assert.equal('manualOverrides' in snapshot, false);
});

test('加密快照可以使用摘要密钥解密并校验 SHA-256', () => {
  const snapshot = createSnapshot([{ id: 1, scope: 'all', enabled: true }]);
  const encrypted = encryptSnapshot(snapshot, Buffer.alloc(32, 7));
  const newline = encrypted.payload.indexOf(10);
  const header = JSON.parse(encrypted.payload.subarray(0, newline).toString('utf8'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(encrypted.key, 'base64url'), Buffer.from(header.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(header.tag, 'base64'));
  const compressed = Buffer.concat([decipher.update(encrypted.payload.subarray(newline + 1)), decipher.final()]);
  const plain = zlib.gunzipSync(compressed);
  assert.deepEqual(JSON.parse(plain.toString('utf8')), snapshot);
  assert.equal(crypto.createHash('sha256').update(plain).digest('hex'), encrypted.contentSha256);
});

test('分片严格遵守上限且不限制片数', () => {
  const payload = Buffer.alloc((2 * 1024 * 1024) + 35);
  const parts = splitPayload(payload, 1);
  assert.ok(parts.length > 1);
  assert.equal(Buffer.concat(parts).length, payload.length);
  assert.equal(summarizeRules([]).ruleCount, 0);
});

test('完成摘要包含解密密钥与校验信息', () => {
  const text = completionText({
    backupId: 'rules-test', partsTotal: 2, contentSha256: 'a'.repeat(64), backupKey: 'secret-key',
    summary: { ruleCount: 3, enabledCount: 2, disabledCount: 1, globalCount: 1, siteSpecificCount: 2, allowCount: 4, blockCount: 5, policyCount: 2, revisionCount: 9 }
  });
  assert.match(text, /解密密钥：secret-key/);
  assert.match(text, /SHA-256：a{64}/);
  assert.match(text, /分片：2/);
  assert.match(text, /名单：允许 4 \/ 阻止 5/);
  assert.match(text, /策略与历史：策略 2 \/ 修订 9/);
});

test('所有人工规则写入入口都会触发变更备份', () => {
  const controller = fs.readFileSync(path.join(__dirname, '..', 'src', 'controllers', 'AdminController.js'), 'utf8');
  assert.match(controller, /if \(applyToAllSites\) RuleBackupService\.scheduleChangedBackup\(\)/);
  assert.equal((controller.match(/RuleBackupService\.scheduleChangedBackup\(\)/g) || []).length, 10);
});
