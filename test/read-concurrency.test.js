'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { limitReadConcurrency } = require('../src/middlewares/readConcurrency');

test('读取并发限制按访客隔离且请求结束后释放槽位', async () => {
  const app = express();
  app.use((req, res, next) => {
    req.readAccess = { visitorId: String(req.get('X-Test-Visitor') || '') };
    next();
  });
  app.get('/slow', limitReadConcurrency, async (req, res) => {
    await new Promise(resolve => setTimeout(resolve, 80));
    res.json({ code: 200 });
  });

  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const url = `http://127.0.0.1:${server.address().port}/slow`;
  const request = visitor => fetch(url, { headers: { 'X-Test-Visitor': visitor } });

  try {
    const first = request('visitor-a');
    const second = request('visitor-a');
    await new Promise(resolve => setTimeout(resolve, 15));
    const limited = await request('visitor-a');
    const independent = await request('visitor-b');

    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '1');
    assert.equal(independent.status, 200);
    assert.deepEqual((await Promise.all([first, second])).map(response => response.status), [200, 200]);

    const afterRelease = await request('visitor-a');
    assert.equal(afterRelease.status, 200);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
