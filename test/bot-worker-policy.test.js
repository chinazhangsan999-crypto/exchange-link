'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

async function loadWorker() {
  const source = await fs.readFile(path.join(__dirname, '..', 'ops', 'public-edge', 'worker.js'), 'utf8');
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}

test('公共前端仅在 enforce 模式拦截已知 AI 爬虫，off 模式不改变访客路径', async () => {
  const worker = (await loadWorker()).default;
  const assets = { fetch: async () => new Response('<!doctype html><title>ok</title>', { status: 200 }) };
  const makeRequest = () => new Request('https://front.example.com/index.html', {
    headers: {
      'User-Agent': 'Mozilla/5.0 compatible; GPTBot/1.2',
      Cookie: 'track_session=test'
    }
  });

  const enforced = await worker.fetch(makeRequest(), { BOT_GATE_MODE: 'enforce', ASSETS: assets });
  assert.equal(enforced.status, 404);
  assert.equal(await enforced.text(), 'Not Found');

  const disabled = await worker.fetch(makeRequest(), { BOT_GATE_MODE: 'off', ASSETS: assets });
  assert.equal(disabled.status, 200);
  assert.match(await disabled.text(), /<title>ok<\/title>/);
});
