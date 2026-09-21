'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const envModule = path.join(__dirname, '..', 'src', 'config', 'env.js');
const baseEnv = {
  ...process.env,
  NODE_ENV: 'production',
  SESSION_SECRET: 's'.repeat(32),
  ADMIN_JWT_SECRET: 'a'.repeat(32),
  GUEST_JWT_SECRET: 'g'.repeat(32),
  FRONTEND_PROXY_SECRET: 'f'.repeat(32),
  BOT_RISK_CENTER_ENABLED: '1',
  BOT_RISK_CLIENT_ID: 'nav-main',
  BOT_RISK_CLIENT_SECRET: 'r'.repeat(32),
  BOT_RISK_SITE_KEY: 'webring-main'
};

function loadEnv(extra) {
  return spawnSync(process.execPath, ['-e', `require(${JSON.stringify(envModule)})`], {
    env: { ...baseEnv, ...extra },
    encoding: 'utf8'
  });
}

test('生产环境仅在显式开启时接受 RFC1918 风险中心 HTTP 地址', () => {
  const allowed = loadEnv({
    BOT_RISK_CENTER_URL: 'http://10.128.0.3:4100',
    BOT_RISK_ALLOW_PRIVATE_HTTP: '1'
  });
  assert.equal(allowed.status, 0, allowed.stderr);

  const publicHttp = loadEnv({
    BOT_RISK_CENTER_URL: 'http://203.0.113.10:4100',
    BOT_RISK_ALLOW_PRIVATE_HTTP: '1'
  });
  assert.notEqual(publicHttp.status, 0);
  assert.match(publicHttp.stderr, /RFC1918 私网 HTTP/);
});

test('observe 模式也必须配置浏览器通行证签名密钥', () => {
  const missing = loadEnv({
    BOT_GATE_MODE: 'observe',
    BOT_RISK_CENTER_URL: 'http://10.128.0.3:4100',
    BOT_RISK_ALLOW_PRIVATE_HTTP: '1',
    EDGE_ACCESS_SECRET: ''
  });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /EDGE_ACCESS_SECRET/);

  const configured = loadEnv({
    BOT_GATE_MODE: 'observe',
    BOT_RISK_CENTER_URL: 'http://10.128.0.3:4100',
    BOT_RISK_ALLOW_PRIVATE_HTTP: '1',
    EDGE_ACCESS_SECRET: 'e'.repeat(32)
  });
  assert.equal(configured.status, 0, configured.stderr);
});
