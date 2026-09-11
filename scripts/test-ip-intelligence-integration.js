'use strict';

const assert = require('assert');
const { run, get, closeDatabase } = require('../src/config/database');
const { initializeDatabase } = require('../src/models/SystemModel');
const IpProfileModel = require('../src/models/IpProfileModel');
const LogModel = require('../src/models/LogModel');

async function main() {
  assert(process.env.DB_PATH, '测试必须显式指定临时 DB_PATH');
  await initializeDatabase();
  await IpProfileModel.initializeIpProfileTable();
  await IpProfileModel.enqueue('1.1.1.1');
  let due = await IpProfileModel.listDue(10);
  assert.equal(due.length, 1);
  assert.equal(due[0].ip_key, '1.1.1.1');

  await IpProfileModel.saveResolved('1.1.1.1', {
    ip_version: 4,
    network_type: 'cdn',
    country_code: 'AU',
    country_name: 'Australia',
    asn: 13335,
    asn_org: 'Cloudflare, Inc.',
    is_hosting: true,
    is_mobile: null,
    is_proxy: null,
    is_vpn: null,
    is_tor: false,
    is_anycast: null,
    confidence: 'high'
  }, 'test:1');

  const saved = await get('SELECT * FROM ip_profiles WHERE ip_key = ?', ['1.1.1.1']);
  assert.equal(saved.lookup_status, 'resolved');
  assert.equal(saved.network_type, 'cdn');
  assert.equal(saved.is_hosting, 1);
  assert.equal(saved.is_mobile, null);
  assert.equal(saved.asn, 13335);
  due = await IpProfileModel.listDue(10);
  assert.equal(due.length, 0);

  const partner = await run(`INSERT INTO partners(name, domain, url, category, is_approved)
    VALUES ('测试站点', 'example.com', 'https://example.com', '常用推荐', 1)`);
  await run(`INSERT INTO inbound_logs(link_id, client_ip, user_agent, created_at)
    VALUES (?, '1.1.1.1', 'Test Browser', CURRENT_TIMESTAMP)`, [partner.id]);
  await LogModel.recordRejectedInbound({
    clientIp: '1.1.1.1', partnerId: partner.id, stage: 'source', reasonCode: 'test'
  });
  const accepted = await LogModel.searchInboundLogs('', { page: 1, pageSize: 10 });
  const rejected = await LogModel.searchRejectedInboundLogs('', { page: 1, pageSize: 10 });
  assert.equal(accepted.items[0].ip_network_type, 'cdn');
  assert.equal(accepted.items[0].ip_asn, 13335);
  assert.equal(rejected.items[0].ip_network_type, 'cdn');
  console.log('IP 情报本地缓存测试通过');
}

main()
  .finally(() => closeDatabase())
  .catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
