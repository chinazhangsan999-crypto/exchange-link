/**
 * 流量链路自检脚本：验证 /go 出站流水、延迟心跳入站流水及仪表盘聚合是否一致。
 * 运行前请先启动 server.js；脚本会写入两条使用保留测试网段 IP 的真实测试流水。
 */
const path = require('path');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const { getLocalDayUtcRange } = require('./src/utils/time');

const BASE_URL = String(process.env.TRAFFIC_TEST_BASE_URL || 'http://127.0.0.1:3001').replace(/\/$/, '');
const DB_PATH = process.env.TRAFFIC_TEST_DB || path.join(__dirname, 'webring.db');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const USER_AGENT = 'Mozilla/5.0 (TrafficSelfCheck/1.0; Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122 Safari/537.36';
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const db = new sqlite3.Database(DB_PATH, sqlite3.OPEN_READONLY);
const reports = [];

/** 将 sqlite 回调查询包装为 Promise，脚本只读检查线上流水。 */
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row)));
}

/** 输出统一的中文体检条目。 */
function report(ok, title, detail = '') {
  reports.push({ ok, title, detail });
  console.log(`${ok ? '✅' : '❌'} ${title}${detail ? `：${detail}` : ''}`);
}

/** 从 Set-Cookie 响应头提取下一次请求所需的 Cookie。 */
function cookieHeader(response) {
  const cookies = response.headers['set-cookie'] || [];
  return cookies.map(item => String(item).split(';')[0]).join('; ');
}

/** 关闭只读数据库连接后按检测结论返回进程状态。 */
function finish() {
  db.close();
  const failed = reports.filter(item => !item.ok);
  console.log('\n──────── 流量链路体检报告 ────────');
  console.log(`通过 ${reports.length - failed.length} 项，失败 ${failed.length} 项。`);
  if (failed.length) {
    console.log('定位建议：确认 server.js 已启动、/go 已由前台卡片使用、管理员账号配置正确，以及 inbound_logs/outbound_logs 表迁移已完成。');
    process.exitCode = 1;
  }
}

async function main() {
  const link = await dbGet('SELECT id, url, domain FROM partners WHERE is_approved = 1 ORDER BY id ASC LIMIT 1');
  if (!link) throw new Error('数据库中没有已审核友链，无法执行流量测试');

  // 使用 RFC 5737 保留测试地址，避免污染真实访客 IP；每次运行均生成新地址以绕过 60 秒防刷窗口。
  const suffix = 1 + Math.floor(Math.random() * 250);
  const outboundIp = `198.51.100.${suffix}`;
  const inboundIp = `203.0.113.${suffix}`;

  console.log(`开始检测：${BASE_URL}，测试友链 #${link.id}（${link.domain}）\n`);

  // 阶段一：出站中转不跟随外部跳转，只验证本机 /go 的 302 及 SQLite 写入。
  const outboundResponse = await axios.get(`${BASE_URL}/go?id=${link.id}`, {
    maxRedirects: 0,
    validateStatus: () => true,
    headers: { 'X-Forwarded-For': outboundIp, 'User-Agent': USER_AGENT }
  });
  report(outboundResponse.status === 302, '出站路由正常', `HTTP ${outboundResponse.status}`);
  const outboundLog = await dbGet(
    "SELECT id, client_ip, created_at FROM outbound_logs WHERE link_id = ? AND client_ip = ? ORDER BY id DESC LIMIT 1",
    [link.id, outboundIp]
  );
  report(Boolean(outboundLog), '出站 SQLite 写入成功', outboundLog ? `${outboundLog.client_ip} @ ${outboundLog.created_at}` : '未找到对应 outbound_logs 记录');

  // 阶段二：先以有效 Referer 访问首页领取 HttpOnly 追踪 Cookie，再等待 3 秒后发起真实心跳。
  const homepage = await axios.get(`${BASE_URL}/`, {
    validateStatus: () => true,
    headers: { Referer: link.url, 'X-Forwarded-For': inboundIp, 'User-Agent': USER_AGENT }
  });
  const cookies = cookieHeader(homepage);
  report(homepage.status === 200 && /(?:track_session|inflow_claim)=/.test(cookies), '入站凭证签发正常', cookies ? '已获取短效追踪 Cookie' : '响应未携带追踪 Cookie');
  if (!/(?:track_session|inflow_claim)=/.test(cookies)) throw new Error('无法取得入站追踪 Cookie；请检查 Referer 域名是否与已审核友链匹配');

  await wait(3100);
  const ping = await axios.post(`${BASE_URL}/api/track/ping`, {
    action: 'ping', trigger: 'traffic-self-check',
    fingerprint: { resolution: '1920x1080', language: 'zh-CN', platform: 'Win32', webdriver: false, abnormalScreen: false, missingLanguage: false, hasUserInteraction: true }
  }, {
    validateStatus: () => true,
    headers: { Cookie: cookies, 'Content-Type': 'application/json', 'X-Forwarded-For': inboundIp, 'User-Agent': USER_AGENT }
  });
  report(ping.status === 200 && ping.data?.code === 200, '入站心跳接口正常', ping.data?.msg || `HTTP ${ping.status}`);
  const inboundLog = await dbGet(
    'SELECT id, client_ip, created_at FROM inbound_logs WHERE link_id = ? AND client_ip = ? ORDER BY id DESC LIMIT 1',
    [link.id, inboundIp]
  );
  report(Boolean(inboundLog), '入站 SQLite 写入成功', inboundLog ? `${inboundLog.client_ip} @ ${inboundLog.created_at}` : '未找到对应 inbound_logs 记录');

  // 阶段三：登录后台读取仪表盘，并以相同日期前缀 SQL 与接口返回值做精确比对。
  const login = await axios.post(`${BASE_URL}/api/admin/login`, { username: ADMIN_USERNAME, password: ADMIN_PASSWORD }, { validateStatus: () => true });
  if (login.status !== 200 || login.data?.code !== 200 || !login.data?.data?.token) throw new Error(`管理员登录失败：${login.data?.msg || `HTTP ${login.status}`}`);
  const statsResponse = await axios.get(`${BASE_URL}/api/admin/dashboard/stats`, { headers: { Authorization: `Bearer ${login.data.data.token}` }, validateStatus: () => true });
  if (statsResponse.status !== 200 || statsResponse.data?.code !== 200) throw new Error(`仪表盘接口失败：${statsResponse.data?.msg || `HTTP ${statsResponse.status}`}`);
  const stats = statsResponse.data.data;
  const { start, end } = getLocalDayUtcRange();
  const actualInbound = Number((await dbGet('SELECT COUNT(DISTINCT client_ip) AS count FROM inbound_logs WHERE created_at >= ? AND created_at < ?', [start, end]))?.count || 0);
  const actualOutbound = Number((await dbGet('SELECT COUNT(DISTINCT client_ip) AS count FROM outbound_logs WHERE created_at >= ? AND created_at < ?', [start, end]))?.count || 0);
  const apiInbound = Number(stats.todayInbound ?? stats.today_inflow_uv ?? 0);
  const apiOutbound = Number(stats.todayOutbound ?? stats.today_outflow_uv ?? 0);
  report(apiInbound > 0 && apiOutbound > 0, '仪表盘今日流量非零', `入站 ${apiInbound} / 出站 ${apiOutbound}`);
  report(apiInbound === actualInbound, '今日入站统计精确匹配', `API ${apiInbound} / SQLite ${actualInbound}`);
  report(apiOutbound === actualOutbound, '今日出站统计精确匹配', `API ${apiOutbound} / SQLite ${actualOutbound}`);
}

main().catch(error => {
  report(false, '体检执行失败', error.message);
}).finally(finish);
