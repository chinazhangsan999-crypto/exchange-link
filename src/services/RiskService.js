'use strict';

const UAParser = require('ua-parser-js');
const PartnerModel = require('../models/PartnerModel');
const LogModel = require('../models/LogModel');
const SystemModel = require('../models/SystemModel');
const RiskAlertModel = require('../models/RiskAlertModel');
const { runPromisePool } = require('../utils/asyncPool');

const asNumber = value => Number(value || 0);
const ratio = (numerator, denominator, digits = 4) => denominator ? Number((numerator / denominator).toFixed(digits)) : 0;

function dashboardRiskReasons(item) {
  const pv = asNumber(item.pv_24h);
  const uv = asNumber(item.score_24h);
  const pvUv = uv ? pv / uv : 0;
  const topIpRatio = pv ? asNumber(item.top_ip_requests) / pv : 0;
  const reasons = [];
  if (pvUv >= 4 && pv >= 20) reasons.push('PV/UV 异常偏高');
  if (topIpRatio >= 0.35) reasons.push('单一 IP 请求占比过高');
  if (uv >= 30 && asNumber(item.outflow_clicks) === 0) reasons.push('高 UV 但无出站点击');
  return { reasons, pv, uv, pvUv, topIpRatio };
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
  const [{ summary, inflowLogs, requestRows, interaction, hourlyPeak }, thresholds] = await Promise.all([
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
  const interactedUv = asNumber(interaction?.interacted_uv);
  const attributedVisits = asNumber(interaction?.attributed_inbound_visits);
  const peakHourlyUv = asNumber(hourlyPeak?.peak_hourly_uv);
  const emptyRefererCount = asNumber(summary.empty_referer_count);
  const pvUvRatio = ratio(pv, uv, 2);
  // 仅统计同一签名访问会话在 30 分钟内的后续出站，不再用“同 IP 任意点击”冒充转化。
  const attributedInteractionRate = ratio(interactedUv, attributedVisits);
  const emptyRefererRatio = ratio(emptyRefererCount, pv);
  const diagnostics = {
    // 风控只生成审核信号；历史记录没有 visit_id 时不进行“低互动”判定。
    zero_conversion: uv > 100 && attributedVisits > 0 && attributedInteractionRate < thresholds.min_interaction_rate,
    interaction_rate: attributedInteractionRate,
    interacted_uv: interactedUv,
    attributed_inbound_visits: attributedVisits,
    attribution_available: attributedVisits > 0,
    time_burst: uv > 50 && ratio(peakHourlyUv, uv) > thresholds.max_hourly_burst_ratio,
    peak_hourly_ratio: ratio(peakHourlyUv, uv), peak_hourly_uv: peakHourlyUv,
    empty_referer: pv > 0 && emptyRefererRatio > thresholds.empty_referer_threshold,
    empty_referer_ratio: emptyRefererRatio,
    empty_referer_count: emptyRefererCount,
    pv_uv_anomaly: pvUvRatio > thresholds.pv_uv_ratio_threshold, pv_uv_ratio: pvUvRatio, thresholds
  };
  const riskReasons = [];
  if (diagnostics.zero_conversion) riskReasons.push('极低出站交互率');
  if (diagnostics.time_burst) riskReasons.push('1 小时流量集中爆发');
  if (diagnostics.pv_uv_anomaly) riskReasons.push('PV/UV 异常偏高');
  if (diagnostics.empty_referer) riskReasons.push('空 Referer 占比异常');

  const deviceStats = makeStats(deviceCounts, inflowLogs.length, ['电脑', '手机', '平板'], 3);
  const osStats = makeStats(osCounts, inflowLogs.length);
  return {
    partner, pv24h: pv, uv24h: uv, pvUvRatio, outflowClicks: asNumber(partner.outflow_clicks),
    roi: Number((asNumber(partner.outflow_clicks) / (uv + 1)).toFixed(3)), complianceRate: asNumber(summary.compliance_rate),
    device_type_stats: deviceStats, os_stats: osStats, operatingSystems: osStats, browsers: makeStats(browserCounts, inflowLogs.length),
    inflow_ips: clientRows || [], all_inflow_ips: clientRows || [], topIps, diagnostics, riskReasons,
    warnings: { pvUvHigh: diagnostics.pv_uv_anomaly, singleIpHigh: (topIps[0]?.ratio || 0) > 30,
      zeroConversion: diagnostics.zero_conversion, timeBurst: diagnostics.time_burst, emptyReferer: diagnostics.empty_referer }
  };
}

const formatPercent = value => `${(asNumber(value) * 100).toFixed(2)}%`;
const formatDistribution = items => (items || []).slice(0, 10).map(item => `${item.name} ${Number(item.ratio || 0).toFixed(1)}%`).join('、') || '暂无数据';

function formatRiskAlert(report, dashboardReasons) {
  const d = report.diagnostics;
  const reasons = [...new Set([...(dashboardReasons || []), ...(report.riskReasons || [])])];
  return [
    `站点：${report.partner.name}`, `域名：${report.partner.domain}`, `站点 ID：${report.partner.id}`,
    `24h UV / PV：${report.uv24h} / ${report.pv24h}`, `风险原因：${reasons.join('、') || '风控指标异常'}`, '',
    `可归因站内互动率：${formatPercent(d.interaction_rate)}（${d.interacted_uv}/${d.attributed_inbound_visits} 会话，阈值 ${formatPercent(d.thresholds.min_interaction_rate)}）`,
    `1 小时峰值 UV 占比：${formatPercent(d.peak_hourly_ratio)}（阈值 ${formatPercent(d.thresholds.max_hourly_burst_ratio)}）`,
    `PV/UV 比值：${d.pv_uv_ratio}（阈值 ${d.thresholds.pv_uv_ratio_threshold}）`, `ROI：${report.roi}`,
    `该站累计出站点击：${report.outflowClicks}`,
    `空 Referer 占比：${formatPercent(d.empty_referer_ratio)}（阈值 ${formatPercent(d.thresholds.empty_referer_threshold)}）`, '',
    `设备类型：${formatDistribution(report.device_type_stats)}`, `操作系统 Top 10：${formatDistribution(report.os_stats)}`,
    `浏览器 Top 10：${formatDistribution(report.browsers)}`,
    `检测时间：${new Date().toLocaleString('zh-CN', { hour12: false })}`
  ].join('\n');
}

async function scanAndNotify({ sendAdminAlert } = {}) {
  if (typeof sendAdminAlert !== 'function') return { skipped: 'missing_sender' };
  if (!String(await SystemModel.configValue('webhook_url')).trim()) return { skipped: 'missing_webhook' };
  const metrics = await LogModel.listRiskPartnerMetrics();
  const candidates = metrics.map(item => ({ item, ...dashboardRiskReasons(item) })).filter(item => item.reasons.length > 0);
  await RiskAlertModel.resolveInactive(candidates.map(item => item.item.id));
  const analyzed = await runPromisePool(candidates, 3, async candidate => {
    const report = await analyzePartner(candidate.item.id, { includeClients: false });
    if (!report || Number(report.partner.is_whitelisted) === 1) return { skipped: 'whitelisted' };
    const fingerprint = JSON.stringify({ reasons: candidate.reasons.slice().sort(), monitor: report.riskReasons.slice().sort(),
      interaction: Math.round(report.diagnostics.interaction_rate * 1000), burst: Math.round(report.diagnostics.peak_hourly_ratio * 100),
      pvUv: Math.round(report.diagnostics.pv_uv_ratio), emptyReferer: Math.round(report.diagnostics.empty_referer_ratio * 100) });
    return { report, reasons: candidate.reasons, fingerprint };
  }, 15000);

  const reports = analyzed.filter(result => result.status === 'fulfilled' && result.value?.report).map(result => result.value);
  const baselineKey = 'risk_alert_webhook_baselined';
  if (String(await SystemModel.configValue(baselineKey)) !== '1') {
    // 初次部署仅登记当前已存在的风险状态；后续新增、恢复后再出现、风险升级才会告警。
    await Promise.allSettled(reports.map(item => RiskAlertModel.shouldNotify(item.report.partner.id, item.fingerprint)));
    await SystemModel.upsertConfig(baselineKey, '1');
    return { candidates: candidates.length, sent: 0, baselined: reports.length };
  }

  const results = await runPromisePool(reports, 3, async item => {
    const { report, reasons, fingerprint } = item;
    const decision = await RiskAlertModel.shouldNotify(report.partner.id, fingerprint);
    if (!decision.notify) return { skipped: decision.reason };
    const sent = await sendAdminAlert('🚨 疑似刷量预警', formatRiskAlert(report, reasons));
    return { sent: Boolean(sent?.sent), reason: decision.reason };
  }, 15000);
  return { candidates: candidates.length, sent: results.filter(result => result.status === 'fulfilled' && result.value?.sent).length, results };
}

module.exports = { analyzePartner, dashboardRiskReasons, scanAndNotify };
