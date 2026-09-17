'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('公共前台 Worker 将动态健康图片转发到 API 源站', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'ops', 'public-edge', 'worker.js'), 'utf8');
  assert.match(source, /'\/.well-known\/route-health\.gif'/);
  assert.match(source, /if \(shouldProxy\(url\.pathname\)\) return await proxyRequest/);

  const apiEdgeSource = fs.readFileSync(path.join(__dirname, '..', 'ops', 'api-edge', 'worker.js'), 'utf8');
  assert.match(apiEdgeSource, /'\/.well-known\/route-health\.gif'/);
  assert.match(apiEdgeSource, /if \(!isAllowedPath\(url\.pathname\)\) return notFound/);
});
