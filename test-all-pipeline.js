/**
 * 全链路集成测试：入站防刷、出站中转、动态榜单、流量免检与仪表盘统计。
 *
 * 运行前请先启动服务：npm start
 * 运行命令：node test-all-pipeline.js
 * 可选配置：BASE_URL=http://127.0.0.1:3001 ADMIN_USERNAME=admin ADMIN_PASSWORD=你的密码 node test-all-pipeline.js
 *
 * 脚本仅插入名称以 E2E_TEST_ 开头的临时站点和 TEST- 前缀 IP，finally 中会自动清理。
 */
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { getLocalDayUtcRange } = require('./src/utils/time');

const BASE_URL = (process.env.BASE_URL || 'http://127.0.0.1:3001').replace(/\/$/, '');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'webring.db');
const runKey = crypto.randomBytes(5).toString('hex');
const prefix = `E2E_TEST_${runKey}`;
const db = new sqlite3.Database(DB_PATH);
const createdPartnerIds = [];
let passed = 0;
let failed = 0;

const run = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, function onRun(error) {
  if (error) reject(error); else resolve({ id: this.lastID, changes: this.changes });
}));
const get = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row)));
const all = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows)));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const client = axios.create({ baseURL: BASE_URL, timeout: 15000, validateStatus: () => true });

function report(ok, title, detail = '') {
  if (ok) { passed += 1; console.log(`✅ ${title}${detail ? `：${detail}` : ''}`); }
  else { failed += 1; console.error(`❌ ${title}${detail ? `：${detail}` : ''}`); }
  if (!ok) throw new Error(`${title}${detail ? `：${detail}` : ''}`);
}

function cookieHeader(setCookie = []) {
  return setCookie.map(item => item.split(';')[0]).join('; ');
}

function testIp(offset) {
  // TEST-NET-2 保留地址，确保不会与真实用户 IP 混淆。
  return `198.51.100.${20 + offset}`;
}

async function insertPartner(name, offset) {
  const domain = `${runKey}-${offset}.e2e.invalid`;
  const result = await run(
    "INSERT INTO partners(name, domain, url, category, is_approved, priority, backlink_status) VALUES (?, ?, ?, '常用推荐', 1, 0, 'valid')",
    [name, domain, `https://${domain}`]
  );
  createdPartnerIds.push(result.id);
  return { id: result.id, domain, url: `https://${domain}` };
}

async function issueTrackingToken(partner, ip, userAgent) {
  const homepage = await client.get('/', {
    headers: { Referer: `${partner.url}/links`, 'X-Forwarded-For': ip, 'User-Agent': userAgent }
  });
  report(homepage.status === 200, '首页追踪会话签发', `HTTP ${homepage.status}`);
  const cookies = cookieHeader(homepage.headers['set-cookie'] || []);
  const tokenResponse = await client.get('/api/inflow/token', { headers: { Cookie: cookies, 'X-Forwarded-For': ip, 'User-Agent': userAgent } });
  const token = tokenResponse.data?.data?.token;
  report(Boolean(token), '入站 Token 获取', token ? '已获取一次性 Token' : '未获取 Token');
  return { token, cookies };
}

async function testInboundFlow(partner) {
  console.log('\n[测试 1] 防刷与入站上报链路');
  const ip = testIp(1);
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36';
  const session = await issueTrackingToken(partner, ip, ua);
  await sleep(3200);
  const payload = { token: session.token, trigger: 'e2e-test', fingerprint: { resolution: '1920x1080', language: 'zh-CN', platform: 'Win32', webdriver: false, abnormalScreen: false, missingLanguage: false, hasUserInteraction: true } };
  const firstPing = await client.post('/api/track/ping', payload, { headers: { Cookie: session.cookies, 'X-Forwarded-For': ip, 'User-Agent': ua } });
  report(firstPing.status === 200 && firstPing.data?.code === 200, '真实停留后入站上报', firstPing.data?.msg || `HTTP ${firstPing.status}`);

  const replayPing = await client.post('/api/track/ping', payload, { headers: { Cookie: session.cookies, 'X-Forwarded-For': ip, 'User-Agent': ua } });
  // 未配置 TRUSTED_PROXIES 时服务端会正确忽略测试传入的 X-Forwarded-For，故按临时站点核对实际记录。
  const inboundRows = await get('SELECT COUNT(*) AS count FROM inbound_logs WHERE link_id = ?', [partner.id]);
  const scoreRows = await get("SELECT COUNT(*) AS count FROM inbound_logs WHERE link_id = ? AND created_at >= datetime('now', '-24 hours')", [partner.id]);
  report(replayPing.status === 409 && Number(inboundRows.count) === 1 && Number(scoreRows.count) === 1, '同 Token 重放与 24h 计分去重', `重放 HTTP ${replayPing.status}，积分 ${scoreRows.count}`);

  const botIp = testIp(2);
  const beforeBotTokens = await get('SELECT COUNT(*) AS count FROM inflow_claim_tokens WHERE partner_id = ?', [partner.id]);
  await client.get('/', { headers: { Referer: `${partner.url}/links`, 'X-Forwarded-For': botIp, 'User-Agent': 'python-requests/2.32' } });
  const afterBotTokens = await get('SELECT COUNT(*) AS count FROM inflow_claim_tokens WHERE partner_id = ?', [partner.id]);
  report(Number(beforeBotTokens.count) === Number(afterBotTokens.count), '爬虫 User-Agent 拦截', 'python-requests 未获得入站凭证');
}

async function testOutboundFlow(partner) {
  console.log('\n[测试 2] 中转重定向与出站流水');
  const ip = testIp(3);
  const response = await client.get(`/go?id=${partner.id}`, { maxRedirects: 0, headers: { 'X-Forwarded-For': ip, 'User-Agent': 'Mozilla/5.0 E2E Browser' } });
  report(response.status === 302 && response.headers.location === partner.url, '中转路由 302 跳转', `Location: ${response.headers.location || '缺失'}`);
  const log = await get('SELECT link_id, client_ip, created_at FROM outbound_logs WHERE link_id = ? ORDER BY id DESC LIMIT 1', [partner.id]);
  report(Boolean(log && Number(log.link_id) === partner.id && log.client_ip && log.created_at), 'outbound_logs 出站流水写入', `${log?.client_ip || '未知 IP'} · ${log?.created_at || '无记录'}`);
}

async function testRanking() {
  console.log('\n[测试 3] 24 小时动态窗口排序');
  const high = await insertPartner(`${prefix}_RANK_HIGH`, 10);
  const middle = await insertPartner(`${prefix}_RANK_MIDDLE`, 11);
  const low = await insertPartner(`${prefix}_RANK_LOW`, 12);
  const seed = async (partner, count, hoursAgo, block) => {
    for (let i = 0; i < count; i += 1) {
      await run("INSERT INTO inbound_logs(link_id, client_ip, user_agent, created_at) VALUES (?, ?, 'E2E Ranking', datetime('now', ?))", [partner.id, testIp(block + i), `-${hoursAgo} hours`]);
    }
  };
  // 三组记录分别处在 2h、8h、20h；都属于 24h 滑动窗口，并以不同 UV 验证动态榜单排序。
  await seed(high, 12, 2, 30);
  await seed(middle, 6, 8, 50);
  await seed(low, 3, 20, 60);
  // 公开列表有 30 秒内存缓存，等待失效后再断言真实 SQL 结果。
  await sleep(31000);
  const response = await client.get('/api/links');
  const ranked = response.data?.data?.links || [];
  const positions = [high.id, middle.id, low.id].map(id => ranked.findIndex(item => Number(item.id) === id));
  const scored = [high.id, middle.id, low.id].map(id => ranked.find(item => Number(item.id) === id)?.score_24h);
  report(positions.every(position => position >= 0) && positions[0] < positions[1] && positions[1] < positions[2] && scored.join(',') === '12,6,3', '近 24h 聚合排序', `UV: ${scored.join(' > ')}，位置: ${positions.join(' < ')}`);
}

async function testTrafficExemption(partner) {
  console.log('\n[测试 4] 流量免检巡检机制');
  await run("UPDATE partners SET backlink_status = 'lost', failed_check_count = 2 WHERE id = ?", [partner.id]);
  const row = await get(`SELECT p.id, COALESCE(recent.rolling_ips, 0) AS traffic_24h
    FROM partners p LEFT JOIN (
      SELECT link_id, COUNT(DISTINCT client_ip) AS rolling_ips FROM inbound_logs
      WHERE created_at >= datetime('now', '-24 hours') GROUP BY link_id
    ) recent ON recent.link_id = p.id WHERE p.id = ?`, [partner.id]);
  // 这里严格执行生产 checkAllBacklinks 中的免检更新语句；不发起 HTTP 请求。
  if (Number(row?.traffic_24h) > 0) await run("UPDATE partners SET backlink_status = 'valid', failed_check_count = 0, last_checked_at = datetime('now') WHERE id = ?", [partner.id]);
  const updated = await get('SELECT backlink_status, failed_check_count, last_checked_at FROM partners WHERE id = ?', [partner.id]);
  report(Number(row?.traffic_24h) > 0 && updated.backlink_status === 'valid' && Number(updated.failed_check_count) === 0 && Boolean(updated.last_checked_at), '近 24h 有流量时巡检短路', `24h UV ${row?.traffic_24h || 0}，未执行网络抓取`);
}

async function testDashboard() {
  console.log('\n[测试 5] 控制台今日数据概览');
  const login = await client.post('/api/admin/login', { username: ADMIN_USERNAME, password: ADMIN_PASSWORD });
  report(login.status === 200 && login.data?.data?.token, '管理员登录获取统计权限', login.data?.msg || `HTTP ${login.status}`);
  const dashboard = await client.get('/api/admin/dashboard/stats', { headers: { Authorization: `Bearer ${login.data.data.token}` } });
  const { start, end } = getLocalDayUtcRange();
  const inbound = await get('SELECT COUNT(DISTINCT client_ip) AS count FROM inbound_logs WHERE created_at >= ? AND created_at < ?', [start, end]);
  const outbound = await get('SELECT COUNT(DISTINCT client_ip) AS count FROM outbound_logs WHERE created_at >= ? AND created_at < ?', [start, end]);
  const matches = Number(dashboard.data?.data?.todayInbound) === Number(inbound.count) && Number(dashboard.data?.data?.todayOutbound) === Number(outbound.count);
  report(dashboard.status === 200 && matches, '仪表盘入站/出站独立 IP 对账', `API ${dashboard.data?.data?.todayInbound}/${dashboard.data?.data?.todayOutbound}，数据库 ${inbound.count}/${outbound.count}`);
}

async function cleanup() {
  if (!createdPartnerIds.length) return;
  const placeholders = createdPartnerIds.map(() => '?').join(',');
  // 显式删除流水，兼容测试连接没有启用 foreign_keys 的 SQLite 环境。
  await run(`DELETE FROM inbound_logs WHERE link_id IN (${placeholders})`, createdPartnerIds);
  await run(`DELETE FROM outbound_logs WHERE link_id IN (${placeholders})`, createdPartnerIds);
  await run(`DELETE FROM inflow_events WHERE partner_id IN (${placeholders})`, createdPartnerIds);
  await run(`DELETE FROM inflow_claim_tokens WHERE partner_id IN (${placeholders})`, createdPartnerIds);
  await run(`DELETE FROM partners WHERE id IN (${placeholders})`, createdPartnerIds);
}

(async () => {
  console.log(`\n=== 星环导航全链路体检开始（${BASE_URL}） ===`);
  try {
    const health = await client.get('/api/config/public');
    report(health.status === 200, '服务连通性', `HTTP ${health.status}`);
    const inboundPartner = await insertPartner(`${prefix}_INBOUND`, 1);
    await testInboundFlow(inboundPartner);
    await testOutboundFlow(inboundPartner);
    await testRanking();
    await testTrafficExemption(inboundPartner);
    await testDashboard();
  } catch (error) {
    if (!String(error.message || '').startsWith('服务连通性')) console.error(`\n定位建议：${error.response ? `接口返回 HTTP ${error.response.status}` : error.message}`);
  } finally {
    try { await cleanup(); console.log('🧹 已清理本次 E2E 临时数据。'); } catch (error) { console.error(`⚠️ 临时数据清理失败：${error.message}`); }
    db.close();
    console.log(`=== 体检结束：通过 ${passed} 项，失败 ${failed} 项 ===`);
    process.exitCode = failed ? 1 : 0;
  }
})();
