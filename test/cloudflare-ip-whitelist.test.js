'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const service = require('../src/services/CloudflareIpWhitelistService');
const helper = require('../ops/cloudflare-ip-sync-helper');

const IPV4 = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
];
const IPV6 = [
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'
];

test('Cloudflare 官方 CIDR 清单会严格校验 IP 版本与最低数量', () => {
  assert.deepEqual(service.parseOfficialList(IPV4.join('\n'), 4), IPV4);
  assert.deepEqual(service.parseOfficialList(IPV6.join('\n'), 6), IPV6);
  assert.throws(() => service.parseOfficialList('127.0.0.1/32', 4), /数量异常/);
  assert.throws(() => service.parseOfficialList([...IPV4.slice(0, 14), 'not-an-ip/24'].join('\n'), 4), /格式不合法/);
});

test('Caddy 片段解析和官网差异计算保持 IPv4、IPv6 分离', () => {
  const fragment = fs.readFileSync(path.join(__dirname, '..', 'ops', 'cloudflare-ips.caddy'), 'utf8');
  const configured = service.parseCaddyFragment(fragment);
  assert.deepEqual(configured, { ipv4: IPV4, ipv6: IPV6 });
  assert.deepEqual(helper.parseFragment(fragment), configured);

  const changed = { ipv4: IPV4.slice(1), ipv6: [...IPV6, '2001:db8::/32'] };
  assert.deepEqual(service.compareLists({ ipv4: IPV4, ipv6: IPV6 }, changed), {
    synchronized: false,
    missing: { ipv4: [IPV4[0]], ipv6: [] },
    extra: { ipv4: [], ipv6: ['2001:db8::/32'] }
  });
});

test('仪表盘状态读取会实时对照官网清单与仓库默认服务器清单', async () => {
  const fetchImpl = async url => new Response(
    String(url).endsWith('ips-v4') ? IPV4.join('\n') : IPV6.join('\n'),
    { status: 200, headers: { 'Content-Type': 'text/plain' } }
  );
  const status = await service.getStatus({ forceOfficial: true, fetchImpl });
  assert.equal(status.official.source, 'cloudflare-live');
  assert.equal(status.configured.source, 'repository-fallback');
  assert.equal(status.comparison.synchronized, true);
});

test('后台仪表盘包含白名单展示、差异信息与手动同步入口', () => {
  const dashboard = fs.readFileSync(path.join(__dirname, '..', 'public', 'admin', 'dashboard.js'), 'utf8');
  const routes = fs.readFileSync(path.join(__dirname, '..', 'src', 'routes', 'admin.js'), 'utf8');
  const caddy = fs.readFileSync(path.join(__dirname, '..', 'ops', 'Caddyfile'), 'utf8');
  assert.match(dashboard, /Cloudflare 官网当前白名单/);
  assert.match(dashboard, /服务器当前设计白名单/);
  assert.match(dashboard, /立即核对并同步/);
  assert.match(routes, /cloudflare\/ip-whitelist\/sync/);
  assert.match(caddy, /import cloudflare-ips\.caddy/);
});
