'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const runId = String(process.env.INFLOW_AUDIT_RUN_ID || new Date().toISOString().replace(/[:.]/g, '-'));
const artifactDirectory = path.resolve(process.env.INFLOW_AUDIT_ARTIFACT_DIR || path.join('backups', `inflow-audit-${runId}`));
fs.mkdirSync(artifactDirectory, { recursive: true });

const { run, get, closeDatabase } = require('../src/config/database');
const { initializeDatabase } = require('../src/models/SystemModel');
const LogModel = require('../src/models/LogModel');

const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36 InflowAudit/1.0';
const results = [];

function auditIp(group, index) {
  return `198.18.${group}.${index + 1}`;
}

function attemptId(group, index) {
  return `audit-${runId}-${group}-${String(index + 1).padStart(3, '0')}`.slice(0, 64);
}

function visitorHash(group, index) {
  return crypto.createHash('sha256').update(`${runId}:${group}:${index}`).digest('hex');
}

async function recordValid(partnerId, group, index, ip, expectedNewUv) {
  const token = crypto.randomBytes(24).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const currentAttemptId = attemptId(group, index);
  await LogModel.createClaimToken({
    tokenHash,
    partnerId,
    ip,
    ttlSeconds: 24 * 60 * 60,
    startedAtMs: Date.now() - 4000,
    referer: '',
    attributionMethod: 'sid_fallback_no_referer',
    observedDomain: '',
    userAgent,
    visitorHash: visitorHash(group, index),
    requestPath: '/',
    attemptId: currentAttemptId
  });
  const claim = await LogModel.getActiveClaim(tokenHash);
  const outcome = await LogModel.processTrackPing({
    tokenHash,
    claim,
    clientIp: ip,
    userAgent,
    visitId: crypto.randomUUID(),
    visitorHash: claim.visitor_hash,
    clientFingerprint: crypto.createHash('sha256').update(`${userAgent}:${ip}`).digest('hex'),
    screenResolution: '1920x1080',
    clientLanguage: 'zh-CN',
    clientPlatform: 'Win32'
  });
  results.push({ group, index: index + 1, attemptId: currentAttemptId, ip, expected: expectedNewUv ? 'new_uv' : 'pv_only', outcome });
}

async function recordRejected(partnerId, group, index, ip, reasonCode, reasonText, classification = 'rejected') {
  const currentAttemptId = attemptId(group, index);
  await LogModel.recordRejectedInbound({
    clientIp: ip,
    visitorHash: visitorHash(group, index),
    userAgent,
    partnerId,
    attributionMethod: group === 'source' ? '' : 'sid_fallback_no_referer',
    visitorType: 'source_validation',
    stage: reasonCode === 'entry_cooldown' ? 'claim_issue' : reasonCode === 'unregistered_source_domain' ? 'source_resolution' : 'heartbeat',
    reasonCode,
    reasonText,
    requestPath: '/',
    attemptId: currentAttemptId,
    classification
  });
  results.push({ group, index: index + 1, attemptId: currentAttemptId, ip, expected: classification });
}

async function main() {
  if (!process.env.DB_PATH) throw new Error('必须通过 DB_PATH 指向专用测试数据库，禁止使用默认数据库');
  await initializeDatabase();
  const domain = `audit-${runId.toLowerCase().replace(/[^a-z0-9-]/g, '').slice(-32)}.test.invalid`;
  const insert = await run(`INSERT INTO partners(
    name, domain, url, category, description, priority, is_approved, backlink_status, ping_status
  ) VALUES (?, ?, ?, ?, ?, 0, 1, 'pending', 'ok')`, [
    `带量审计 ${runId}`, domain, `https://${domain}`, '__AUDIT__', '500条隔离测试专用记录'
  ]);
  const partnerId = Number(insert.id);

  // A：100 个独立访客，全部应新增 UV。
  for (let index = 0; index < 100; index += 1) {
    await recordValid(partnerId, 'valid-unique', index, auditIp(1, index), true);
  }

  // B：20 个 IP 各产生 5 次有效心跳，共 100 PV，仅前 20 次新增 UV。
  for (let index = 0; index < 100; index += 1) {
    const ipIndex = index % 20;
    await recordValid(partnerId, 'valid-repeat', index, auditIp(2, ipIndex), index < 20);
  }

  // C：50 次重复入口被抑制，随后各自通过另一凭证成功；同 IP 可同时留在两张事实表，但抑制记录必须被核销。
  for (let index = 0; index < 50; index += 1) {
    const ip = auditIp(3, index);
    await recordRejected(partnerId, 'cooldown', index, ip, 'entry_cooldown', '重复请求已抑制（测试）', 'suppressed');
    await recordValid(partnerId, 'cooldown-valid', index, ip, true);
  }

  // D-G：四类真正未通过校验的请求，各 50 条。
  for (let index = 0; index < 50; index += 1) {
    await recordRejected(partnerId, 'short-stay', index, auditIp(4, index), 'stay_too_short', '页面停留时间不足3秒');
    await recordRejected(partnerId, 'environment', index, auditIp(5, index), 'environment_mismatch', 'IP、User-Agent 或访问环境校验未通过');
    await recordRejected(partnerId, 'source', index, auditIp(6, index), 'unregistered_source_domain', '来源域名未登记，无法归属到友链');
    await recordRejected(partnerId, 'expired', index, auditIp(7, index), 'heartbeat_expired', '15分钟内未完成有效心跳');
  }

  const counts = await get(`SELECT
    (SELECT COUNT(*) FROM inbound_logs WHERE link_id = ?) AS inbound_rows,
    (SELECT COUNT(DISTINCT client_ip) FROM inbound_logs WHERE link_id = ?) AS score_uv,
    (SELECT COUNT(*) FROM inbound_rejection_logs WHERE partner_id = ?) AS rejection_rows,
    (SELECT COUNT(*) FROM inbound_rejection_logs WHERE partner_id = ? AND classification = 'suppressed') AS suppressed_rows,
    (SELECT COUNT(*) FROM inbound_rejection_logs WHERE partner_id = ? AND resolution_status = 'resolved_by_valid_visit') AS resolved_rows,
    (SELECT COUNT(DISTINCT r.client_ip) FROM inbound_rejection_logs r
      JOIN inbound_logs i ON i.link_id = r.partner_id AND i.client_ip = r.client_ip
      WHERE r.partner_id = ?) AS ips_in_both,
    (SELECT COUNT(DISTINCT r.client_ip) FROM inbound_rejection_logs r
      JOIN inbound_logs i ON i.link_id = r.partner_id AND i.client_ip = r.client_ip
      WHERE r.partner_id = ? AND r.classification = 'rejected') AS rejected_ips_in_both,
    (SELECT COUNT(*) FROM inbound_rejection_logs r
      JOIN inbound_logs i ON i.link_id = r.partner_id AND i.attempt_id = r.attempt_id
      WHERE r.partner_id = ? AND r.attempt_id <> '') AS attempt_ids_in_both,
    (SELECT COUNT(*) FROM inbound_rejection_logs
      WHERE partner_id = ? AND classification = 'suppressed' AND resolution_status = 'unresolved') AS unresolved_suppressed_rows`,
  [partnerId, partnerId, partnerId, partnerId, partnerId, partnerId, partnerId, partnerId, partnerId]);

  const acceptedPages = [];
  const rejectedPages = [];
  for (let page = 1; page <= 3; page += 1) {
    acceptedPages.push((await LogModel.searchInboundLogs(domain, { page, pageSize: 100 })).items.length);
    rejectedPages.push((await LogModel.searchRejectedInboundLogs(domain, { page, pageSize: 100 })).items.length);
  }

  const observed = {
    totalCases: results.length,
    newlyCounted: results.filter(item => item.outcome?.newlyCounted === true).length,
    duplicatePv: results.filter(item => item.outcome?.newlyCounted === false).length,
    counts: Object.fromEntries(Object.entries(counts).map(([key, value]) => [key, Number(value)])),
    acceptedPages,
    rejectedPages
  };
  const expected = {
    totalCases: 500,
    inboundRows: 250,
    scoreUv: 170,
    rejectionRows: 250,
    suppressedRows: 50,
    resolvedRows: 50,
    ipsInBoth: 50,
    rejectedIpsInBoth: 0,
    attemptIdsInBoth: 0,
    unresolvedSuppressedRows: 0,
    newlyCounted: 170,
    duplicatePv: 80,
    acceptedPages: [100, 100, 50],
    rejectedPages: [100, 100, 50]
  };
  const assertions = [
    ['测试场景总数', observed.totalCases, expected.totalCases],
    ['有效带量事实行数', observed.counts.inbound_rows, expected.inboundRows],
    ['24h 去重积分 UV', observed.counts.score_uv, expected.scoreUv],
    ['未通过/抑制事实行数', observed.counts.rejection_rows, expected.rejectionRows],
    ['重复请求抑制行数', observed.counts.suppressed_rows, expected.suppressedRows],
    ['抑制后成功核销行数', observed.counts.resolved_rows, expected.resolvedRows],
    ['同时存在两表的 IP 数', observed.counts.ips_in_both, expected.ipsInBoth],
    ['真正拒绝后又有效的 IP 数', observed.counts.rejected_ips_in_both, expected.rejectedIpsInBoth],
    ['同一 attempt_id 同时成功与失败', observed.counts.attempt_ids_in_both, expected.attemptIdsInBoth],
    ['未核销的重复请求抑制行数', observed.counts.unresolved_suppressed_rows, expected.unresolvedSuppressedRows],
    ['新增 UV 返回次数', observed.newlyCounted, expected.newlyCounted],
    ['重复仅 PV 返回次数', observed.duplicatePv, expected.duplicatePv],
    ['有效明细分页', JSON.stringify(observed.acceptedPages), JSON.stringify(expected.acceptedPages)],
    ['未通过明细分页', JSON.stringify(observed.rejectedPages), JSON.stringify(expected.rejectedPages)]
  ].map(([name, actual, wanted]) => ({ name, actual, expected: wanted, passed: actual === wanted }));
  const passed = assertions.every(item => item.passed);
  const payload = { runId, database: path.resolve(process.env.DB_PATH), partnerId, domain, expected, observed, assertions, passed, cases: results };
  fs.writeFileSync(path.join(artifactDirectory, 'results.json'), JSON.stringify(payload, null, 2));
  fs.writeFileSync(path.join(artifactDirectory, 'test-cases.json'), JSON.stringify(results, null, 2));
  const report = [
    `# 500 条入站链路审计报告`, '',
    `- 运行编号：${runId}`,
    `- 测试站点 ID：${partnerId}`,
    `- 测试域名：${domain}`,
    `- 总结：${passed ? '全部断言通过' : '存在断言失败'}`, '',
    '| 检查项 | 实际 | 预期 | 结果 |', '|---|---:|---:|---|',
    ...assertions.map(item => `| ${item.name} | ${item.actual} | ${item.expected} | ${item.passed ? '通过' : '失败'} |`), '',
    '## 数据解释', '',
    '- 有效带量表记录每一次通过完整校验的心跳，因此包含 PV。',
    '- 24 小时积分按同一站点的独立 IP 计算，因此重复有效心跳不会重复加分。',
    '- 重复入口被抑制属于请求级审计，不代表此前领取的凭证失败；后续有效心跳会将其标记为已解决。',
    '- 同一 IP 出现在两张表是允许的，但必须来自不同 attempt_id，并由 resolution_status 明确说明后续结果。', ''
  ].join('\n');
  fs.writeFileSync(path.join(artifactDirectory, 'report.md'), report);
  console.log(JSON.stringify({ artifactDirectory, partnerId, passed, observed, assertions }, null, 2));
  if (!passed) process.exitCode = 1;
}

main()
  .catch(error => {
    console.error(error.stack || error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDatabase().catch(error => console.error('关闭测试数据库失败：', error.message));
  });
