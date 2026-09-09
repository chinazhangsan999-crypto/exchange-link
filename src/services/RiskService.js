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

/** Shared by the admin monitor and the Webhook scanner. includeClients=false excludes IP/client rows. */
async function analyzePartner(partnerId, { includeClients = true } = {}) {
  const partner = await PartnerModel.findAnalyticsPartner(Number(partnerId));
  if (!partner) return null;
  const [{ summary, inflowLogs, requestRows, deadWaterInteraction, attributedInteraction, hourlyPeak }, thresholds] = await Promise.all([
    LogModel.getPartnerAnalytics(partner.id),
    SystemModel.getRiskControlConfig()
  ]);
  const pv = asNumber(summary.pv);
  const uv = asNumber(summary.uv || inflowLogs.length);
  const requestMap = new Map(requestRows.map(row => [row.ip, row]));
  const deviceCounts = new Map();
  const osCounts = new Map();
  const browserCounts = new Map();
  const clientRows = includeClients ? [] : null;

  for (const log of inflowLogs) {
    const parsed = new UAParser(log.user_agent || '').getResult();
    const deviceType = normalizeType(parsed);
    const osName = parsed.os.name || '未知系统';
    const browserName = parsed.browser.name || '未知浏览器';
    deviceCounts.set(deviceType, (deviceCounts.get(deviceType) || 0) + 1);
    osCounts.set(osName, (osCounts.get(osName) || 0) + 1);
    browserCounts.set(browserName, (browserCounts.get(browserName) || 0) + 1);
    if (clientRows) {
      const requests = asNumber(requestMap.get(log.ip)?.requests || 1);
      const client = clientName(parsed);
      clientRows.push({ ip: log.ip, client, device_model: client, device_type: deviceType, timestamp: log.timestamp,
        requests, ratio: pv ? Number((requests * 100 / pv).toFixed(1)) : 0 });
    }
  }

  const topIps = (clientRows || []).slice().sort((a, b) => b.requests - a.requests || String(b.timestamp).localeCompare(String(a.timestamp))).slice(0, 10);
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
    inflow_ips: clientRows || [], all_inflow_ips: clientRows || [], topIps, diagnostics, risk, riskReasons,
    warnings: { pvUvHigh: diagnostics.pv_uv_anomaly, singleIpHigh: (topIps[0]?.ratio || 0) > 30,
      deadWaterLow: diagnostics.dead_water_low, attributedInteractionLow: diagnostics.attributed_interaction_low,
      timeBurst: diagnostics.time_burst, emptyReferer: diagnostics.empty_referer }
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

module.exports = { analyzePartner, dashboardRiskReasons, buildRiskAssessment, scanAndNotify };
