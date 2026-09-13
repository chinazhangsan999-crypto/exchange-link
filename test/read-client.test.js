'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const vm = require('node:vm');

function jsonResponse(status, body) {
  return {
    status,
    ok: status >= 200 && status < 300,
    async json() { return body; },
    clone() { return jsonResponse(status, body); }
  };
}

async function loadClient(fetchMock) {
  const source = await fs.readFile(path.join(__dirname, '..', 'public', 'read-client.js'), 'utf8');
  const window = {};
  vm.runInNewContext(source, {
    window,
    fetch: fetchMock,
    Headers,
    Set,
    Date,
    TypeError,
    Promise
  });
  return window;
}

test('并发页面组件共享一次读取凭证请求', async () => {
  let bootstrapCalls = 0;
  const protectedHeaders = [];
  const window = await loadClient(async (url, init) => {
    if (url === '/api/read/bootstrap') {
      bootstrapCalls += 1;
      await new Promise(resolve => setTimeout(resolve, 10));
      return jsonResponse(200, {
        code: 200,
        data: { token: 'token-one', expiresAt: Date.now() + 60000 }
      });
    }
    protectedHeaders.push(init.headers);
    return jsonResponse(200, { code: 200, data: {} });
  });

  await Promise.all([
    window.readApiFetch('/api/links'),
    window.readApiFetch('/api/showcase')
  ]);

  assert.equal(bootstrapCalls, 1);
  assert.equal(protectedHeaders.length, 2);
  assert.ok(protectedHeaders.every(headers => headers.get('X-Read-Token') === 'token-one'));
});

test('凭证失效后自动续签并且原请求只重试一次', async () => {
  let bootstrapCalls = 0;
  let protectedCalls = 0;
  const usedTokens = [];
  const window = await loadClient(async (url, init) => {
    if (url === '/api/read/bootstrap') {
      bootstrapCalls += 1;
      return jsonResponse(200, {
        code: 200,
        data: { token: `token-${bootstrapCalls}`, expiresAt: Date.now() + 60000 }
      });
    }
    protectedCalls += 1;
    usedTokens.push(init.headers.get('X-Read-Token'));
    return protectedCalls === 1
      ? jsonResponse(428, { code: 428 })
      : jsonResponse(200, { code: 200, data: {} });
  });

  await window.readAccessReady;
  const response = await window.readApiFetch('/api/links');

  assert.equal(response.status, 200);
  assert.equal(bootstrapCalls, 2);
  assert.equal(protectedCalls, 2);
  assert.deepEqual(usedTokens, ['token-1', 'token-2']);
});

test('相同展示接口的并发读取合并为一个网络请求', async () => {
  let protectedCalls = 0;
  const window = await loadClient(async url => {
    if (url === '/api/read/bootstrap') {
      return jsonResponse(200, {
        code: 200,
        data: { token: 'shared-token', expiresAt: Date.now() + 60000 }
      });
    }
    protectedCalls += 1;
    await new Promise(resolve => setTimeout(resolve, 10));
    return jsonResponse(200, { code: 200, data: { source: 'shared' } });
  });

  const [first, second] = await Promise.all([
    window.readApiFetch('/api/links'),
    window.readApiFetch('/api/links')
  ]);

  assert.equal(protectedCalls, 1);
  assert.equal((await first.json()).data.source, 'shared');
  assert.equal((await second.json()).data.source, 'shared');
});

test('三个不同读取任务在前端排队且同时最多执行两个', async () => {
  let activeProtectedReads = 0;
  let maxActiveProtectedReads = 0;
  const window = await loadClient(async url => {
    if (url === '/api/read/bootstrap') {
      return jsonResponse(200, {
        code: 200,
        data: { token: 'queue-token', expiresAt: Date.now() + 60000 }
      });
    }
    activeProtectedReads += 1;
    maxActiveProtectedReads = Math.max(maxActiveProtectedReads, activeProtectedReads);
    await new Promise(resolve => setTimeout(resolve, 20));
    activeProtectedReads -= 1;
    return jsonResponse(200, { code: 200, data: {} });
  });

  const responses = await Promise.all([
    window.readApiFetch('/api/links'),
    window.readApiFetch('/api/links/3'),
    window.readApiFetch('/api/showcase')
  ]);

  assert.equal(maxActiveProtectedReads, 2);
  assert.deepEqual(responses.map(response => response.status), [200, 200, 200]);
});

test('首页与详情页在业务脚本之前加载读取客户端', async () => {
  for (const filename of ['index.html', 'site-detail.html']) {
    const html = await fs.readFile(path.join(__dirname, '..', 'public', filename), 'utf8');
    assert.ok(html.indexOf('/read-client.js') >= 0, `${filename} 缺少读取客户端`);
    assert.ok(html.indexOf('/read-client.js') < html.indexOf('/common.js'), `${filename} 脚本顺序错误`);
  }
});
