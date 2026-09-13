'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { securityHeaders } = require('../src/middlewares/security');

test('全站响应要求搜索引擎不收录且不跟踪链接', () => {
  const headers = new Map();
  const res = {
    setHeader(name, value) {
      headers.set(String(name).toLowerCase(), value);
    }
  };
  let called = false;

  securityHeaders({}, res, () => {
    called = true;
  });

  assert.equal(called, true);
  assert.equal(headers.get('x-robots-tag'), 'noindex, nofollow');
});

test('robots.txt 禁止所有搜索引擎抓取全站', () => {
  const file = path.join(__dirname, '..', 'public', 'robots.txt');
  const content = fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n').trim();

  assert.equal(content, 'User-agent: *\nDisallow: /');
});
