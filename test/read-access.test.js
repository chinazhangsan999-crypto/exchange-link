'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('公开展示接口使用短效读取凭证且不影响直接打开首页', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'webring-read-access-'));
  process.env.DB_PATH = path.join(directory, 'webring.db');
  process.env.SESSION_SECRET = 'test-session-secret-0123456789';
  process.env.ADMIN_JWT_SECRET = 'test-admin-secret-01234567890';
  process.env.GUEST_JWT_SECRET = 'test-guest-secret-01234567890';
  process.env.INITIAL_ADMIN_PASSWORD = 'LocalTestPassword123';

  const database = require('../src/config/database');
  const SystemModel = require('../src/models/SystemModel');
  const AdsModel = require('../src/models/AdsModel');
  const app = require('../src/app');

  await SystemModel.initializeDatabase();
  await AdsModel.initializeAdsTable();
  const server = app.listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  async function bootstrap() {
    const response = await fetch(`${baseUrl}/api/read/bootstrap`);
    const body = await response.json();
    const visitorCookie = response.headers.getSetCookie()
      .find(value => value.startsWith('guest_visitor_id='))
      .split(';', 1)[0];
    return { response, body, visitorCookie };
  }

  try {
    const homepage = await fetch(`${baseUrl}/`);
    assert.equal(homepage.status, 200);

    const visitorA = await bootstrap();
    assert.equal(visitorA.response.status, 200);
    assert.equal(visitorA.response.headers.get('cache-control'), 'private, no-store');
    assert.equal(visitorA.body.code, 200);
    assert.equal(visitorA.body.data.expiresIn, 60);
    assert.ok(visitorA.body.data.token);

    const missingToken = await fetch(`${baseUrl}/api/links`, {
      headers: { Cookie: visitorA.visitorCookie }
    });
    assert.equal(missingToken.status, 428);

    const allowed = await fetch(`${baseUrl}/api/links`, {
      headers: {
        Cookie: visitorA.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.headers.get('cache-control'), 'private, no-store');
    assert.equal((await allowed.json()).code, 200);

    const visitorB = await bootstrap();
    const crossVisitor = await fetch(`${baseUrl}/api/links`, {
      headers: {
        Cookie: visitorB.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(crossVisitor.status, 403);

    const wrongScope = await fetch(`${baseUrl}/api/showcase`, {
      headers: {
        Cookie: visitorA.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(wrongScope.status, 200);

    const firstTrap = await fetch(`${baseUrl}/api/sys-trap/trapdoor`, {
      headers: { Cookie: visitorA.visitorCookie }
    });
    assert.equal(firstTrap.status, 204);
    assert.equal(firstTrap.headers.get('cache-control'), 'private, no-store');
    const afterFirstSignal = await fetch(`${baseUrl}/api/links`, {
      headers: {
        Cookie: visitorA.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(afterFirstSignal.status, 200);

    const secondTrap = await fetch(`${baseUrl}/api/sys-trap/trapdoor`, {
      headers: { Cookie: visitorA.visitorCookie }
    });
    assert.equal(secondTrap.status, 204);
    const restrictedVisitor = await fetch(`${baseUrl}/api/links`, {
      headers: {
        Cookie: visitorA.visitorCookie,
        'X-Read-Token': visitorA.body.data.token
      }
    });
    assert.equal(restrictedVisitor.status, 429);
    assert.equal(restrictedVisitor.headers.get('retry-after'), '30');

    // 两个访客来自同一个测试 IP；A 的风险状态不得连坐 B。
    const sameNatOtherVisitor = await fetch(`${baseUrl}/api/links`, {
      headers: {
        Cookie: visitorB.visitorCookie,
        'X-Read-Token': visitorB.body.data.token
      }
    });
    assert.equal(sameNatOtherVisitor.status, 200);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await database.closeDatabase();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
