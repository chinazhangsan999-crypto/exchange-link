'use strict';

const UAParser = require('ua-parser-js');
const PartnerModel = require('../models/PartnerModel');
const LogModel = require('../models/LogModel');
const SystemModel = require('../models/SystemModel');
const RiskAlertModel = require('../models/RiskAlertModel');
const { runPromisePool } = require('../utils/asyncPool');
const { formatAlertLink, formatContactLine } = require('./AlertService');

const asNumber = value => Number(value || 0);
const ratio = (numerator, denominator, digits = 4) => denominator ? Number((numerator / denominator).toFixed(digits)) : 0;
const MIN_ALERT_UV = 30;
const MIN_ATTRIBUTED_SESSIONS = 10;
const SINGLE_IP_RATIO_THRESHOLD = 0.35;
let riskScanInProgress = false;

function buildRiskAssessment(uv, diagnostics) {
  const attributedVisits = asNumber(diagnostics.attributed_inbound_visits);
  if (uv < MIN_ALERT_UV || attributedVisits < MIN_ATTRIBUTED_SESSIONS) {
    return {
      alertable: false,
      level: null,
      reasons: [],
      data_insufficient: true,
      sample_note: uv < MIN_ALERT_UV
        ? `近24h UV 少于 ${MIN_ALERT_UV}`
        : `可归因会话少于 ${MIN_ATTRIBUTED_SESSIONS}`
    };
  }

  const highReasons = [];
  const mediumReasons = [];
  if (diagnostics.dead_water_low) highReasons.push('近24h 死水交互率偏低');
  if (diagnostics.attributed_interaction_low) highReasons.push('30分钟可归因站内互动率偏低');
  if (diagnostics.time_burst) mediumReasons.push('1 小时流量集中爆发');
  if (diagnostics.empty_referer) mediumReasons.push('空 Referer 占比异常');
  if (diagnostics.pv_uv_anomaly) mediumReasons.push('PV/UV 异常偏高');
  if (diagnostics.single_ip_concentrated) mediumReasons.push('单一 IP 请求占比过高');

  const level = highReasons.length ? 'high' : (mediumReasons.length ? 'medium' : null);
  return {
    alertable: Boolean(level),
    level,
    reasons: [...highReasons, ...mediumReasons],
    data_insufficient: false,
    sample_note: ''
  };
}

function dashboardRiskReasons(report) {
  const risk = report?.risk || {};
  return { reasons: risk.reasons || [], level: risk.level || null, dataInsufficient: Boolean(risk.data_insufficient) };
}

function clientName(parsed) {
  const os = [parsed.os.name, parsed.os.version].filter(Boolean).join(' ');
  const browserVersion = parsed.browser.major || String(parsed.browser.version || '').split('.')[0];
  const browser = [parsed.browser.name, browserVersion].filter(Boolean).join(' ');
  return [os || '未知系统', browser || '未知浏览器'].join(' · ');
}

function normalizeType(parsed) {
  return parsed.device.type === 'mobile' ? '手机' : parsed.device.type === 'tablet' ? '平板' : '电脑';
}

function makeStats(map, total, names = [], limit = 10) {
  return names.map(name => ({ name, count: map.get(name) || 0, ratio: total ? Number(((map.get(name) || 0) * 100 / total).toFixed(1)) : 0 }))
    .concat([...map.entries()].filter(([name]) => !names.includes(name)).sort((a, b) => b[1] - a[1])
      .map(([name, count]) => ({ name, count, ratio: total ? Number((count * 100 / total).toFixed(1)) : 0 })))
    .slice(0, limit);
}

function sqliteUtcMilliseconds(value) {
  const raw = String(value || '').trim();
  if (!raw) return 0;
  const normalized = raw.replace(' ', 'T');
  const parsed = Date.parse(/(?:Z|[+-]\d{2}:?\d{2})$/i.test(normalized) ? normalized : `${normalized}Z`);
  return Number.isFinite(parsed) ? parsed : 0;
}

function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function maxEventsInWindow(timestamps, windowMs) {
  let maximum = 0;
  let start = 0;
  for (let end = 0; end < timestamps.length; end += 1) {
    while (timestamps[end] - timestamps[start] > windowMs) start += 1;
    maximum = Math.max(maximum, end - start + 1);
  }
  return maximum;
}

function refererHostname(value) {
  try { return new URL(String(value || '')).hostname.replace(/^www\./i, ''); }
  catch { return ''; }
}

function buildClientAuditRows(events, interactions, pv, thresholds) {
  const groups = new Map();
  const ipCounts = new Map();
  const ipIdentities = new Map();
  const fingerprintIps = new Map();
  const interactionMap = new Map((interactions || []).map(item => [String(item.visit_id || ''), item]));

  for (const event of events || []) {
    const ip = String(event.ip || '未知 IP');
    const visitorHash = String(event.visitor_hash || '');
    const identityKey = visitorHash ? `visitor:${visitorHash}` : `ip:${ip}`;
    if (!groups.has(identityKey)) groups.set(identityKey, { identityKey, visitorHash, events: [], ips: new Set(), uas: new Set(), fingerprints: new Set() });
    const group = groups.get(identityKey);
    group.events.push(event);
    group.ips.add(ip);
    if (event.user_agent) group.uas.add(String(event.user_agent));
    if (event.client_fingerprint) group.fingerprints.add(String(event.client_fingerprint));
    ipCounts.set(ip, (ipCounts.get(ip) || 0) + 1);
    if (!ipIdentities.has(ip)) ipIdentities.set(ip, new Set());
    ipIdentities.get(ip).add(identityKey);
    if (event.client_fingerprint) {
      const fingerprintIpSet = fingerprintIps.get(event.client_fingerprint) || new Set();
      fingerprintIpSet.add(ip);
      fingerprintIps.set(event.client_fingerprint, fingerprintIpSet);
    }
  }

  return [...groups.values()].map(group => {
    const ordered = [...group.events].sort((a, b) => sqliteUtcMilliseconds(b.timestamp) - sqliteUtcMilliseconds(a.timestamp));
    const latest = ordered[0] || {};
    const timestamps = ordered.map(item => sqliteUtcMilliseconds(item.timestamp)).filter(Boolean).sort((a, b) => a - b);
    const intervals = timestamps.slice(1).map((value, index) => Math.max(0, (value - timestamps[index]) / 1000));
    const meanInterval = intervals.length ? intervals.reduce((sum, value) => sum + value, 0) / intervals.length : 0;
    const deviation = intervals.length
      ? Math.sqrt(intervals.reduce((sum, value) => sum + ((value - meanInterval) ** 2), 0) / intervals.length)
      : 0;
    const intervalVariation = meanInterval ? deviation / meanInterval : 1;
    const fixedInterval = intervals.length >= 4 && median(intervals) >= 1 && median(intervals) <= 300 && intervalVariation <= 0.15;
    const visitIds = new Set(ordered.map(item => String(item.visit_id || '')).filter(Boolean));
    let interactedSessions = 0;
    let interactionClicks = 0;
    let firstInteractionSeconds = null;
    for (const visitId of visitIds) {
      const interaction = interactionMap.get(visitId);
      if (!interaction) continue;
      interactedSessions += 1;
      interactionClicks += asNumber(interaction.click_count);
      const delay = asNumber(interaction.first_interaction_seconds);
      if (firstInteractionSeconds === null || delay < firstInteractionSeconds) firstInteractionSeconds = delay;
    }
    const requests = ordered.length;
    const latestIp = String(latest.ip || '未知 IP');
    const ipRequests = asNumber(ipCounts.get(latestIp));
    const emptyRefererCount = ordered.filter(item => !String(item.referer || '').trim()).length;
    const attributionMethods = [...new Set(ordered.map(item => String(item.attribution_method || '')).filter(Boolean))];
    const sourceAnomaly = attributionMethods.some(method => /mismatch|invalid|unknown/i.test(method));
    const environmentIpCount = latest.client_fingerprint
      ? (fingerprintIps.get(latest.client_fingerprint)?.size || 1)
      : 0;
    const noInteraction = visitIds.size >= 5 && interactedSessions === 0;
    const highIpRatio = pv >= 20 && ratio(ipRequests, pv) >= SINGLE_IP_RATIO_THRESHOLD;
    const emptyRefererHigh = requests >= 5 && ratio(emptyRefererCount, requests) > thresholds.empty_referer_threshold;
    const environmentAnomaly = group.uas.size >= 3 || group.ips.size >= 3 || environmentIpCount >= 5;
    const strongReasons = [];
    const observationReasons = [];
    if (highIpRatio) strongReasons.push('单一 IP 请求占比过高');
    if (fixedInterval) strongReasons.push('访问间隔高度规律');
    if (sourceAnomaly) strongReasons.push('来源归属存在异常');
    if (noInteraction) observationReasons.push('多次访问无后续互动');
    if (emptyRefererHigh) observationReasons.push('该客户端空 Referer 偏高');
    if (group.uas.size >= 3) observationReasons.push('客户端 UA 频繁变化');
    if (group.ips.size >= 3) observationReasons.push('同一匿名访客切换多个 IP');
    if (environmentIpCount >= 5) observationReasons.push('相同环境摘要分布于多个 IP');
    if ((ipIdentities.get(latestIp)?.size || 0) >= 5) observationReasons.push('共享 IP 下存在多个匿名访客');
    const riskLevel = strongReasons.length >= 2 ? 'high'
      : (strongReasons.length || observationReasons.length ? 'observe' : 'normal');
    const parsed = new UAParser(latest.user_agent || '').getResult();
    return {
      identity_key: group.identityKey,
      visitor_short: group.visitorHash ? group.visitorHash.slice(-8).toUpperCase() : '',
      ip: latestIp,
      ip_lookup_status: String(latest.ip_lookup_status || 'pending'),
      ip_network_type: String(latest.ip_network_type || 'unknown'),
      ip_country_code: String(latest.ip_country_code || ''),
      ip_country_name: String(latest.ip_country_name || ''),
      ip_region: String(latest.ip_region || ''),
      ip_city: String(latest.ip_city || ''),
      ip_asn: latest.ip_asn == null ? null : Number(latest.ip_asn),
      ip_asn_org: String(latest.ip_asn_org || ''),
      ip_isp: String(latest.ip_isp || ''),
      ip_is_hosting: latest.ip_is_hosting,
      ip_is_mobile: latest.ip_is_mobile,
      ip_is_proxy: latest.ip_is_proxy,
      ip_is_vpn: latest.ip_is_vpn,
      ip_is_tor: latest.ip_is_tor,
      ip_is_anycast: latest.ip_is_anycast,
      ip_confidence: String(latest.ip_confidence || 'unknown'),
      ip_profile_updated_at: String(latest.ip_profile_updated_at || ''),
      ip_count: group.ips.size,
      ip_visitor_count: ipIdentities.get(latestIp)?.size || 1,
      client: clientName(parsed),
      device_model: clientName(parsed),
      device_type: normalizeType(parsed),
      raw_user_agent: String(latest.user_agent || ''),
      screen_resolution: String(latest.screen_resolution || ''),
      client_language: String(latest.client_language || ''),
      client_platform: String(latest.client_platform || ''),
      environment_short: latest.client_fingerprint ? String(latest.client_fingerprint).slice(-8).toUpperCase() : '',
      environment_ip_count: environmentIpCount,
      requests,
      sessions: visitIds.size || requests,
      ratio: ratio(requests, pv) * 100,
      ip_requests: ipRequests,
      ip_ratio: ratio(ipRequests, pv) * 100,
      duplicate_pv: Math.max(0, requests - group.ips.size),
      first_seen: ordered[ordered.length - 1]?.timestamp || '',
      timestamp: latest.timestamp || '',
      duration_seconds: timestamps.length > 1 ? Math.round((timestamps[timestamps.length - 1] - timestamps[0]) / 1000) : 0,
      min_interval_seconds: intervals.length ? Math.round(Math.min(...intervals)) : null,
      median_interval_seconds: intervals.length ? Math.round(median(intervals)) : null,
      // 导航站访问通常在数秒内完成，使用短窗口观察瞬时脚本爆发，
      // 避免 1 分钟/5 分钟窗口把真实的快速点击行为稀释掉。
      max_events_10s: maxEventsInWindow(timestamps, 10 * 1000),
      max_events_20s: maxEventsInWindow(timestamps, 20 * 1000),
      recent_times: ordered.slice(0, 10).map(item => item.timestamp),
      referer: String(latest.referer || ''),
      source_domain: String(latest.observed_domain || refererHostname(latest.referer) || ''),
      attribution_method: String(latest.attribution_method || ''),
      attribution_methods: attributionMethods,
      empty_referer_count: emptyRefererCount,
      ua_count: group.uas.size,
      fingerprint_count: group.fingerprints.size,
      interacted_sessions: interactedSessions,
      interaction_clicks: interactionClicks,
      first_interaction_seconds: firstInteractionSeconds,
      risk_level: riskLevel,
      risk_reasons: [...strongReasons, ...observationReasons],
      flags: {
        risky: riskLevel !== 'normal',
        no_interaction: noInteraction,
        source_anomaly: sourceAnomaly || emptyRefererHigh,
        periodic: fixedInterval,
        environment_anomaly: environmentAnomaly
      }
    };
  }).sort((a, b) => {
    const ranks = { high: 2, observe: 1, normal: 0 };
    return (ranks[b.risk_level] || 0) - (ranks[a.risk_level] || 0)
      || b.ip_ratio - a.ip_ratio
      || String(b.timestamp).localeCompare(String(a.timestamp));
  });
}

/** Shared by the admin monitor and the Webhook scanner. includeClients=false excludes IP/client rows. */
async function analyzePartner(partnerId, { includeClients = true } = {}) {
  const partner = await PartnerModel.findAnalyticsPartner(Number(partnerId));
  if (!partner) return null;
  const [{
    summary, inflowLogs, requestRows, deadWaterInteraction, attributedInteraction, hourlyPeak,
    clientEvents, clientInteractions, clientEventsTruncated
  }, thresholds] = await Promise.all([
    LogModel.getPartnerAnalytics(partner.id, { includeClients }),
    SystemModel.getRiskControlConfig()
  ]);
  const pv = asNumber(summary.pv);
  const uv = asNumber(summary.uv || inflowLogs.length);
  const deviceCounts = new Map();
  const osCounts = new Map();
  const browserCounts = new Map();

  for (const log of inflowLogs) {
    const parsed = new UAParser(log.user_agent || '').getResult();
    const deviceType = normalizeType(parsed);
    const osName = parsed.os.name || '未知系统';
    const browserName = parsed.browser.name || '未知浏览器';
    deviceCounts.set(deviceType, (deviceCounts.get(deviceType) || 0) + 1);
    osCounts.set(osName, (osCounts.get(osName) || 0) + 1);
    browserCounts.set(browserName, (browserCounts.get(browserName) || 0) + 1);
  }

  const allClientRows = includeClients
    ? buildClientAuditRows(clientEvents, clientInteractions, pv, thresholds)
    : [];
  // 风控弹窗只保留最值得优先审核的 300 个客户端，避免异常流量导致浏览器一次渲染数千行。
  const clientRows = allClientRows.slice(0, 300);
  const topIps = clientRows.slice(0, 10);
  const deadWaterInteractedUv = asNumber(deadWaterInteraction?.interacted_uv);
  const deadWaterInboundUv = asNumber(deadWaterInteraction?.inbound_uv || uv);
  const attributedInteractedVisits = asNumber(attributedInteraction?.interacted_visits);
  const attributedVisits = asNumber(attributedInteraction?.attributed_inbound_visits);
  const peakHourlyUv = asNumber(hourlyPeak?.peak_hourly_uv);
  const maxIpRequests = requestRows.reduce((max, row) => Math.max(max, asNumber(row.requests)), 0);
  const emptyRefererCount = asNumber(summary.empty_referer_count);
  const pvUvRatio = ratio(pv, uv, 2);
  const deadWaterInteractionRate = ratio(deadWaterInteractedUv, deadWaterInboundUv);
  // 仅统计同一签名访问会话在 30 分钟内的后续出站，不再用“同 IP 任意点击”冒充转化。
  const attributedInteractionRate = ratio(attributedInteractedVisits, attributedVisits);
  const emptyRefererRatio = ratio(emptyRefererCount, pv);
  const diagnostics = {
    // 两种互动率均只生成审核信号，绝不自动封禁；历史记录没有 visit_id 时不判定可归因互动率。
    dead_water_low: uv >= 100 && deadWaterInboundUv > 0 && deadWaterInteractionRate < thresholds.min_interaction_rate,
    dead_water_interaction_rate: deadWaterInteractionRate,
    dead_water_interacted_uv: deadWaterInteractedUv,
    dead_water_inbound_uv: deadWaterInboundUv,
    attributed_interaction_low: uv >= 100 && attributedVisits > 0 && attributedInteractionRate < thresholds.min_attributed_interaction_rate,
    attributed_interaction_rate: attributedInteractionRate,
    attributed_interacted_visits: attributedInteractedVisits,
    attributed_inbound_visits: attributedVisits,
    attribution_available: attributedVisits > 0,
    time_burst: uv > 50 && ratio(peakHourlyUv, uv) > thresholds.max_hourly_burst_ratio,
    peak_hourly_ratio: ratio(peakHourlyUv, uv), peak_hourly_uv: peakHourlyUv,
    empty_referer: pv > 0 && emptyRefererRatio > thresholds.empty_referer_threshold,
    empty_referer_ratio: emptyRefererRatio,
    empty_referer_count: emptyRefererCount,
    top_ip_ratio: ratio(maxIpRequests, pv),
    single_ip_concentrated: pv >= 20 && ratio(maxIpRequests, pv) >= SINGLE_IP_RATIO_THRESHOLD,
    pv_uv_anomaly: pvUvRatio > thresholds.pv_uv_ratio_threshold, pv_uv_ratio: pvUvRatio, thresholds
  };
  const risk = buildRiskAssessment(uv, diagnostics);
  const riskReasons = risk.reasons;

  const deviceStats = makeStats(deviceCounts, inflowLogs.length, ['电脑', '手机', '平板'], 3);
  const osStats = makeStats(osCounts, inflowLogs.length);
  return {
    partner, pv24h: pv, uv24h: uv, pvUvRatio, outflowClicks: asNumber(partner.outflow_clicks),
    roi: Number((asNumber(partner.outflow_clicks) / (uv + 1)).toFixed(3)), complianceRate: asNumber(summary.compliance_rate),
    device_type_stats: deviceStats, os_stats: osStats, operatingSystems: osStats, browsers: makeStats(browserCounts, inflowLogs.length),
    inflow_ips: clientRows, all_inflow_ips: clientRows,
    client_groups_total: allClientRows.length,
    client_events_truncated: Boolean(clientEventsTruncated || allClientRows.length > clientRows.length),
    topIps, diagnostics, risk, riskReasons,
    warnings: { pvUvHigh: diagnostics.pv_uv_anomaly, singleIpHigh: diagnostics.single_ip_concentrated,
      deadWaterLow: diagnostics.dead_water_low, attributedInteractionLow: diagnostics.attributed_interaction_low,
      timeBurst: diagnostics.time_burst, emptyReferer: diagnostics.empty_referer }
  };
}

/**
 * 风控客户端明细的服务端筛选与分页。
 * KPI 继续由 analyzePartner() 基于完整 24h 聚合计算；这里只分页返回客户端审计行。
 */
async function analyzePartnerClients(partnerId, { page = 1, pageSize = 100, query = '', filter = 'all' } = {}) {
  const partner = await PartnerModel.findAnalyticsPartner(Number(partnerId));
  if (!partner) return null;
  const safePage = Math.max(1, Number.parseInt(page, 10) || 1);
  const safePageSize = Math.max(1, Math.min(100, Number.parseInt(pageSize, 10) || 100));
  const safeFilter = ['all', 'risk', 'noInteraction', 'sourceAnomaly', 'periodic', 'environmentAnomaly'].includes(filter)
    ? filter
    : 'all';
  const normalizedQuery = String(query || '').trim().toLowerCase();
  const [{ summary, clientEvents, clientInteractions, clientEventsTruncated }, thresholds] = await Promise.all([
    LogModel.getPartnerAnalytics(partner.id, { includeClients: true, clientEventLimit: 5000 }),
    SystemModel.getRiskControlConfig()
  ]);
  const pv = asNumber(summary?.pv);
  const allRows = buildClientAuditRows(clientEvents, clientInteractions, pv, thresholds);
  const flagByFilter = {
    risk: 'risky',
    noInteraction: 'no_interaction',
    sourceAnomaly: 'source_anomaly',
    periodic: 'periodic',
    environmentAnomaly: 'environment_anomaly'
  };
  const filteredRows = allRows.filter(row => {
    const flag = flagByFilter[safeFilter];
    if (flag && !row.flags?.[flag]) return false;
    if (!normalizedQuery) return true;
    return [
      row.ip, row.ip_network_type, row.ip_country_name, row.ip_region, row.ip_city,
      row.ip_asn_org, row.ip_isp, row.visitor_short, row.client, row.raw_user_agent, row.source_domain,
      row.referer, ...(row.risk_reasons || [])
    ].some(value => String(value || '').toLowerCase().includes(normalizedQuery));
  });
  const total = filteredRows.length;
  const totalPages = Math.max(1, Math.ceil(total / safePageSize));
  const effectivePage = Math.min(safePage, totalPages);
  const offset = (effectivePage - 1) * safePageSize;
  return {
    items: filteredRows.slice(offset, offset + safePageSize),
    pagination: {
      page: effectivePage,
      pageSize: safePageSize,
      total,
      totalPages,
      from: total ? offset + 1 : 0,
      to: total ? Math.min(offset + safePageSize, total) : 0,
      hasPrevious: effectivePage > 1,
      hasNext: effectivePage < totalPages
    },
    clientGroupsTotal: allRows.length,
    clientEventsTruncated: Boolean(clientEventsTruncated),
    analyzedEventLimit: 5000
  };
}

const formatPercent = value => `${(asNumber(value) * 100).toFixed(2)}%`;
const formatDistribution = items => (items || []).slice(0, 10).map(item => `${item.name} ${Number(item.ratio || 0).toFixed(1)}%`).join('、') || '暂无数据';

function formatRiskAlert(report, dashboardReasons) {
  const d = report.diagnostics;
  const reasons = [...new Set([...(dashboardReasons || []), ...(report.riskReasons || [])])];
  const level = report.risk?.level === 'high' ? '高风险' : '中风险';
  const backlinkUrl = report.partner.backlink_url || report.partner.url;
  return [
    `站点：${report.partner.name}`,
    `域名：${formatAlertLink(report.partner.domain, report.partner.domain, { allowDomain: true })}`,
    `站点网址：${formatAlertLink(report.partner.url, report.partner.url)}`,
    `反链检测网址：${formatAlertLink(backlinkUrl, backlinkUrl)}`,
    ...(!report.partner.backlink_url ? ['说明：未单独配置，默认检测站点网址'] : []),
    formatContactLine('友链站长联系方式', report.partner.contact),
    `站点 ID：${report.partner.id}`,
    `风险等级：${level}`, `24h UV / PV：${report.uv24h} / ${report.pv24h}`,
    `命中规则：${reasons.join('、') || '风控指标异常'}`, `建议动作：人工审核，不自动封禁。`, '',
    `死水交互率（近24h）：${formatPercent(d.dead_water_interaction_rate)}（${d.dead_water_interacted_uv}/${d.dead_water_inbound_uv} 入站 IP，阈值 ${formatPercent(d.thresholds.min_interaction_rate)}；仅供人工审核）`,
    `可归因站内互动率（30min）：${formatPercent(d.attributed_interaction_rate)}（${d.attributed_interacted_visits}/${d.attributed_inbound_visits} 会话，阈值 ${formatPercent(d.thresholds.min_attributed_interaction_rate)}）`,
    `1 小时峰值 UV 占比：${formatPercent(d.peak_hourly_ratio)}（阈值 ${formatPercent(d.thresholds.max_hourly_burst_ratio)}）`,
    `PV/UV 比值：${d.pv_uv_ratio}（阈值 ${d.thresholds.pv_uv_ratio_threshold}）`,
    `空 Referer 占比：${formatPercent(d.empty_referer_ratio)}（阈值 ${formatPercent(d.thresholds.empty_referer_threshold)}）`, '',
    `设备类型：${formatDistribution(report.device_type_stats)}`, `操作系统 Top 10：${formatDistribution(report.os_stats)}`,
    `浏览器 Top 10：${formatDistribution(report.browsers)}`,
    `检测时间：${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })}`
  ].join('\n');
}

async function scanAndNotify({ sendAdminAlert } = {}) {
  if (riskScanInProgress) return { skipped: 'already_running', sent: 0, candidates: 0 };
  if (typeof sendAdminAlert !== 'function') return { skipped: 'missing_sender' };
  const [webhookUrl, barkEnabled, barkDeviceKey] = await Promise.all([
    SystemModel.configValue('webhook_url'), SystemModel.configValue('bark_enabled'), SystemModel.configValue('bark_device_key')
  ]);
  if (!String(webhookUrl).trim() && !(String(barkEnabled) === '1' && String(barkDeviceKey).trim())) {
    return { skipped: 'missing_alert_channel' };
  }
  riskScanInProgress = true;
  try {
  const metrics = await LogModel.listRiskPartnerMetrics();
  // 先按 UV 做成本低的样本量过滤；完整分层判断只能由统一诊断结果得出。
  const candidates = metrics.filter(item => asNumber(item.score_24h) >= MIN_ALERT_UV);
  const analyzed = await runPromisePool(candidates, 3, async candidate => {
    const report = await analyzePartner(candidate.id, { includeClients: false });
    if (!report || Number(report.partner.is_whitelisted) === 1) return { skipped: 'whitelisted' };
    if (!report.risk?.alertable) return { skipped: report.risk?.data_insufficient ? 'insufficient_data' : 'healthy' };
    const fingerprint = JSON.stringify({ level: report.risk.level, reasons: report.riskReasons.slice().sort(),
      deadWater: Math.round(report.diagnostics.dead_water_interaction_rate * 1000),
      attributed: Math.round(report.diagnostics.attributed_interaction_rate * 1000),
      burst: Math.round(report.diagnostics.peak_hourly_ratio * 100),
      pvUv: Math.round(report.diagnostics.pv_uv_ratio), emptyReferer: Math.round(report.diagnostics.empty_referer_ratio * 100) });
    return { report, reasons: report.riskReasons, fingerprint };
  }, 15000);

  const reports = analyzed.filter(result => result.status === 'fulfilled' && result.value?.report).map(result => result.value);
  await RiskAlertModel.resolveInactive(reports.map(item => item.report.partner.id));
  const baselineKey = 'risk_alert_webhook_baselined';
  if (String(await SystemModel.configValue(baselineKey)) !== '1') {
    // 初次部署仅登记当前已存在的风险状态；后续新增、恢复后再出现、风险升级才会告警。
    await Promise.allSettled(reports.map(item => RiskAlertModel.baselineRiskState(item.report.partner.id, item.fingerprint)));
    await SystemModel.upsertConfig(baselineKey, '1');
    return { candidates: candidates.length, sent: 0, baselined: reports.length };
  }

  const results = await runPromisePool(reports, 3, async item => {
    const { report, reasons, fingerprint } = item;
    const decision = await RiskAlertModel.getNotificationDecision(report.partner.id, fingerprint);
    if (!decision.notify) return { skipped: decision.reason };
    const contact = String(report.partner.contact || '').replace(/[\r\n\t]+/g, ' ').trim();
    const sent = await sendAdminAlert('🚨 疑似刷量预警', formatRiskAlert(report, reasons), {
      eventType: 'risk_alert',
      barkUrl: report.partner.url,
      barkCopy: contact
    });
    if (sent?.sent) await RiskAlertModel.markAlertDelivered(report.partner.id, fingerprint);
    else await RiskAlertModel.markAlertFailed(report.partner.id, fingerprint, sent?.reason || '告警通道未送达');
    return { sent: Boolean(sent?.sent), reason: decision.reason };
  }, 15000);
  return { candidates: candidates.length, sent: results.filter(result => result.status === 'fulfilled' && result.value?.sent).length, results };
  } finally {
    riskScanInProgress = false;
  }
}

module.exports = { analyzePartner, analyzePartnerClients, dashboardRiskReasons, buildRiskAssessment, scanAndNotify };
