'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const AlertService = require('../src/services/AlertService');

test('Telegram 与 Bark 文本截断不会切断 Unicode 字符', () => {
  const telegram = AlertService.truncateUnicode('风'.repeat(5000), AlertService.TELEGRAM_TEXT_LIMIT);
  assert.ok([...telegram].length <= AlertService.TELEGRAM_TEXT_LIMIT);
  assert.match(telegram, /进入后台查看$/);

  const bark = AlertService.truncateUtf8('风险告警'.repeat(1000), AlertService.BARK_BODY_BYTES);
  assert.ok(Buffer.byteLength(bark, 'utf8') <= AlertService.BARK_BODY_BYTES);
  assert.match(bark, /进入后台查看$/);
});

test('渠道发送队列遵守最小间隔并保持串行', async () => {
  const starts = [];
  const queue = AlertService.createRateQueue(40, async value => {
    starts.push(Date.now());
    await new Promise(resolve => setTimeout(resolve, 5));
    return value;
  });
  const values = await Promise.all([queue(1), queue(2), queue(3)]);
  assert.deepEqual(values, [1, 2, 3]);
  assert.ok(starts[1] - starts[0] >= 35);
  assert.ok(starts[2] - starts[1] >= 35);
});

test('告警后台与数据库迁移包含敏感凭据保护和聚合阈值', () => {
  const root = path.join(__dirname, '..');
  const html = fs.readFileSync(path.join(root, 'public', 'admin.html'), 'utf8');
  const script = fs.readFileSync(path.join(root, 'public', 'admin.js'), 'utf8');
  const migration = fs.readFileSync(path.join(root, 'migrations', '002_alerting.sql'), 'utf8');
  const storage = fs.readFileSync(path.join(root, 'src', 'services', 'StorageService.js'), 'utf8');
  assert.match(html, /data-tab="alerts"/);
  assert.match(html, /Telegram[\s\S]+Bark[\s\S]+聚合阈值/);
  assert.match(script, /telegramConfigured[\s\S]+barkConfigured/);
  assert.match(migration, /telegram_token_ciphertext/);
  assert.match(migration, /alert_delivery_logs/);
  assert.match(storage, /COUNT\(DISTINCT d\.subject_hash\)/);
  assert.doesNotMatch(storage, /telegramToken:\s*row\./);
});
