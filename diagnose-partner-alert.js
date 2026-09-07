'use strict';

const sqlite3 = require('sqlite3').verbose();
const { requestSafePing } = require('./src/services/PingService');

const db = new sqlite3.Database('/home/niaiwo/app/webring.db', sqlite3.OPEN_READONLY);
const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (error, row) => (error ? reject(error) : resolve(row)));
});
const close = () => new Promise((resolve, reject) => db.close(error => (error ? reject(error) : resolve())));

(async () => {
  const partner = await get(`SELECT id, name, domain, url, ping_exempt, ping_status,
    ping_failed_count, last_ping_at, is_approved FROM partners WHERE id = ?`, [24]);
  const configured = await get("SELECT value FROM site_configs WHERE key = 'webhook_url'");
  let webhook = { configured: false };
  if (configured?.value) {
    try {
      const parsed = new URL(configured.value);
      webhook = { configured: true, host: parsed.hostname, supported: ['api.telegram.org', 'qyapi.weixin.qq.com'].some(host => parsed.hostname === host || parsed.hostname.endsWith(`.${host}`)) };
    } catch {
      webhook = { configured: true, validUrl: false };
    }
  }

  console.log(JSON.stringify({ partner, webhook }, null, 2));
  if (!partner?.url || Number(partner.ping_exempt) === 1) return;

  for (const method of ['HEAD', 'GET']) {
    const startedAt = Date.now();
    try {
      const response = await requestSafePing(partner.url, method, { timeoutMs: 5000 });
      console.log(JSON.stringify({ method, ok: true, status: response.status, elapsedMs: Date.now() - startedAt }));
    } catch (error) {
      console.log(JSON.stringify({ method, ok: false, code: error.code || null, status: error.response?.status || null, message: error.message, elapsedMs: Date.now() - startedAt }));
    }
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
}).finally(async () => {
  await close();
});
