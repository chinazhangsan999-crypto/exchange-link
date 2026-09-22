'use strict';

const StorageService = require('./StorageService');

const SIGNAL_META = Object.freeze({
  cloudflare_confirmed_bot: ['Cloudflare 已确认机器人', '边缘平台已明确识别为自动程序。'],
  verified_search_bot: ['已验证搜索引擎蜘蛛', '来源与已验证搜索引擎蜘蛛一致。'],
  known_ai_crawler: ['已知 AI 爬虫', '客户端特征与已登记的 AI 抓取程序相符。'],
  token_replay: ['读取凭证重放', '短效读取凭证被重复或异常使用。'],
  sequential_detail_scan: ['连续枚举详情页', '短时间内按编号连续读取多个详情页面。'],
  high_concurrency: ['异常并发读取', '核心数据读取并发量超过正常页面行为。'],
  botd_detected: ['浏览器自动化特征', '浏览器环境暴露了自动化框架特征。'],
  webdriver_detected: ['WebDriver 特征', '浏览器报告了 WebDriver 自动控制标识。'],
  browser_automation_confirmed: ['自动化证据确认', '多项浏览器自动化证据同时成立。'],
  script_user_agent: ['脚本型客户端', '客户端标识与常见命令行或程序化请求一致。'],
  trapdoor_hit: ['访问隐藏探针', '访问了正常界面不可见的探针路径。'],
  repeated_trapdoor: ['重复访问隐藏探针', '同一访客多次触发隐藏探针。'],
  challenge_failed: ['浏览器验证失败', '客户端未能通过浏览器静默验证。'],
  missing_fetch_metadata: ['缺少浏览器请求元数据', '请求缺少现代浏览器通常自动携带的 Fetch Metadata。'],
  valid_browser_access: ['有效浏览器通行证', '客户端持有有效浏览器通行状态。'],
  valid_read_token: ['有效读取凭证', '请求经过了正常页面读取流程。'],
  challenge_passed: ['风险验证通过', '客户端已通过风险验证。'],
  browser_challenge_passed: ['浏览器挑战通过', '客户端已通过浏览器挑战。'],
  normal_dwell: ['正常页面停留', '页面停留时间符合常见真人阅读节奏。'],
  outbound_interaction: ['真实出站交互', '访客产生了正常出站点击行为。']
});

const BLOCKED_KEY = /(?:ip|cookie|jwt|sid|token|secret|password|authorization|credential|query|search|referer)/i;
const ALLOWED_EVIDENCE = new Set([
  'path', 'requestPath', 'method', 'userAgent', 'ua', 'concurrency', 'count',
  'detailCount', 'detailId', 'ids', 'windowMs', 'reason', 'source', 'botName',
  'botKind', 'elapsedMs', 'difficultyBits', 'webdriver', 'botDetected',
  'secFetchSite', 'secFetchMode', 'secFetchDest', 'test'
]);

function cleanPath(value) {
  const text = String(value || '').slice(0, 500);
  try { return new URL(text, 'https://redacted.invalid').pathname.slice(0, 300); }
  catch { return text.split(/[?#]/, 1)[0].slice(0, 300); }
}

function normalizeClient(value) {
  const ua = String(value || '');
  const os = /Windows NT 10\.0/i.test(ua) ? 'Windows 10/11'
    : /Android ([\d.]+)/i.test(ua) ? `Android ${RegExp.$1}`
      : /(?:iPhone|iPad).*OS ([\d_]+)/i.test(ua) ? `iOS ${RegExp.$1.replaceAll('_', '.')}`
        : /Mac OS X ([\d_]+)/i.test(ua) ? `macOS ${RegExp.$1.replaceAll('_', '.')}` : '未知系统';
  const browser = /Edg\/([\d.]+)/i.test(ua) ? `Edge ${RegExp.$1.split('.')[0]}`
    : /CriOS\/([\d.]+)/i.test(ua) ? `Chrome Mobile ${RegExp.$1.split('.')[0]}`
      : /Chrome\/([\d.]+)/i.test(ua) ? `Chrome ${RegExp.$1.split('.')[0]}`
        : /Firefox\/([\d.]+)/i.test(ua) ? `Firefox ${RegExp.$1.split('.')[0]}`
          : /Version\/([\d.]+).*Safari/i.test(ua) ? `Safari ${RegExp.$1.split('.')[0]}` : '未知客户端';
  return `${os} · ${browser}`;
}

function sanitizeEvidence(evidence) {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return {};
  const output = {};
  for (const [key, raw] of Object.entries(evidence)) {
    if (!ALLOWED_EVIDENCE.has(key) || BLOCKED_KEY.test(key) || raw === null || raw === '') continue;
    if (key === 'path' || key === 'requestPath') output.path = cleanPath(raw);
    else if (key === 'userAgent' || key === 'ua') output.client = normalizeClient(raw);
    else if (Array.isArray(raw)) output[key] = raw.slice(0, 20).map(item => String(item).slice(0, 100));
    else if (['string', 'number', 'boolean'].includes(typeof raw)) output[key] = typeof raw === 'string' ? raw.slice(0, 300) : raw;
  }
  return output;
}

function signalInfo(signal) {
  const [label, explanation] = SIGNAL_META[signal] || [signal, '系统记录到该信号，建议结合其它证据人工复核。'];
  return { label, explanation };
}

function summarize(item) {
  const strongest = [...(item.signals || [])].sort((a, b) => Math.abs(b.scoreImpact) - Math.abs(a.scoreImpact))[0];
  return strongest ? signalInfo(strongest.signal).label : '需要人工复核';
}

function mapSuspect(item) {
  return {
    siteKey: item.siteKey,
    siteName: item.siteName,
    visitorHash: item.visitorHash,
    riskScore: item.score,
    decision: item.decision,
    summary: summarize(item),
    signals: (item.signals || []).map(signal => ({
      signal: signal.signal,
      ...signalInfo(signal.signal),
      count: signal.count,
      scoreImpact: signal.scoreImpact,
      firstSeenAt: signal.firstSeen,
      lastSeenAt: signal.lastSeen,
      latestEvidence: sanitizeEvidence(signal.latestEvidence)
    })),
    firstSeenAt: item.firstSeen,
    lastSeenAt: item.lastSeen,
    eventCount: item.eventCount,
    manualAction: item.manualAction || null,
    manualReason: item.manualReason || null
  };
}

async function list(input, access) {
  const result = await StorageService.listAnalysisSuspects(input, access.siteKeys);
  return { ...result, items: result.items.map(mapSuspect) };
}

async function detail(siteKey, visitorHash, access) {
  if (!access.siteKeys.includes(siteKey)) return null;
  const item = await StorageService.getSuspectDetail(siteKey, visitorHash);
  if (!item) return null;
  const mapped = mapSuspect({ ...item, firstSeen: item.events.at(-1)?.occurredAt, lastSeen: item.events[0]?.occurredAt, eventCount: item.events.length });
  return {
    ...mapped,
    decisionAt: item.decisionAt,
    expiresAt: item.expiresAt,
    events: item.events.map(event => ({
      eventType: event.eventType,
      ...signalInfo(event.eventType),
      occurredAt: event.occurredAt,
      evidence: sanitizeEvidence(event.evidence)
    }))
  };
}

async function exportPackage(input, access) {
  const subjects = (input.subjects || []).slice(0, 100);
  let result;
  let items;
  if (subjects.length || input.selectedOnly === true) {
    items = (await Promise.all(subjects.map(subject => detail(
      String(subject.siteKey || ''), String(subject.visitorHash || '').toLowerCase(), access
    )))).filter(Boolean);
    result = { filters: { selected: true } };
  } else {
    result = await list({ ...input, page: 1, limit: 100 }, access);
    items = result.items;
  }
  return {
    schema: 'risk-analysis-package-v1',
    generatedAt: new Date().toISOString(),
    readOnly: true,
    filters: result.filters,
    total: items.length,
    items
  };
}

module.exports = { list, detail, exportPackage, sanitizeEvidence, normalizeClient, signalInfo };
