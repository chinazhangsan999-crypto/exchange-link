'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

test('后台生成的浏览器通行证密钥可热加载并支持安全轮换', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-browser-secret-'));
  process.env.BROWSER_ACCESS_SECRET_FILE = path.join(directory, 'browser-access.json');
  delete process.env.EDGE_ACCESS_SECRET;

  const store = require('../src/services/BrowserAccessSecretStore');
  const challenge = require('../src/services/BrowserChallengeService');

  try {
    assert.equal(store.status().configured, false);
    const generated = await store.ensureSecret(1_700_000_000_000);
    assert.equal(generated.configured, true);
    assert.equal(generated.source, 'managed');
    assert.match(generated.fingerprint, /^[a-f0-9]{4}…[a-f0-9]{4}$/);
    assert.equal(Object.hasOwn(generated, 'currentSecret'), false);

    const oldToken = challenge.issueAccessToken('visitor-1', 'Test Browser', 'browser', 1_700_000_001_000);
    assert.ok(challenge.verifyAccessToken(oldToken, 'visitor-1', 'Test Browser', 1_700_000_001_500));

    const rotated = await store.rotateSecret(1_700_000_002_000);
    assert.notEqual(rotated.fingerprint, generated.fingerprint);
    assert.ok(rotated.previousValidUntil);
    assert.ok(challenge.verifyAccessToken(oldToken, 'visitor-1', 'Test Browser', 1_700_000_002_500));

    const newToken = challenge.issueAccessToken('visitor-1', 'Test Browser', 'browser', 1_700_000_003_000);
    assert.ok(challenge.verifyAccessToken(newToken, 'visitor-1', 'Test Browser', 1_700_000_003_500));

    const persisted = JSON.parse(await fs.readFile(process.env.BROWSER_ACCESS_SECRET_FILE, 'utf8'));
    assert.ok(String(persisted.current_secret).length >= 32);
    assert.notEqual(persisted.current_secret, persisted.previous_secret);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
