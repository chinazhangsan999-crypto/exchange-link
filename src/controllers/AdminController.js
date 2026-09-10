'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const UAParser = require('ua-parser-js');
const { ZipArchive } = require('archiver');
const { parse: parseCsv } = require('csv-parse/sync');
const { ADMIN_JWT_SECRET } = require('../config/env');
const { parseHostname, matchesPartnerDomain, normalizePartnerUrl } = require('../utils/network');
const { normalizeUrl, normalizeAnalyticsScriptUrl } = require('../utils/url');
const { buildSourceEntryUrls } = require('../utils/sourceLinks');
const { ok, fail, safeApiErrorMessage, isUniqueConstraintError } = require('../utils/http');
const PartnerModel = require('../models/PartnerModel');
const LogModel = require('../models/LogModel');
const SystemModel = require('../models/SystemModel');
const AdModel = require('../models/AdsModel');
const MirrorModel = require('../models/MirrorModel');
const SourceTokenModel = require('../models/SourceTokenModel');
const InspectionService = require('../services/InspectionService');
const PingService = require('../services/PingService');
const RiskService = require('../services/RiskService');
const SiteTrafficService = require('../services/SiteTrafficService');
const CacheService = require('../services/CacheService');
const WebhookDeliveryModel = require('../models/WebhookDeliveryModel');
const { sendAdminAlert, sendBarkTestAlert, providerForUrl } = require('../services/AlertService');
const InspectionAlertService = require('../services/InspectionAlertService');
const { runTrackedJob } = require('../jobs/cron');
const { runPromisePool } = require('../utils/asyncPool');

const ANALYTICS_CONFIG_KEYS = [
  'umami_enabled',
  'umami_script_url',
  'umami_website_id',
  'cf_analytics_enabled',
  'cf_beacon_token',
  'clarity_enabled',
  'clarity_project_id',
  'generic_analytics_enabled',
  'generic_analytics_code'
];
const ANALYTICS_ENABLED_KEYS = new Set([
  'umami_enabled',
  'cf_analytics_enabled',
  'clarity_enabled',
  'generic_analytics_enabled'
]);

const INSPECTION_JOB_TTL_MS = 30 * 60 * 1000;
const INSPECTION_JOB_LIMIT = 100;
const inspectionJobs = new Map();

function cleanupInspectionJobs(now = Date.now()) {
  for (const [jobId, job] of inspectionJobs) {
    if (job.status !== 'running' && Number(job.finishedAt || 0) + INSPECTION_JOB_TTL_MS <= now) {
      inspectionJobs.delete(jobId);
    }
  }
  if (inspectionJobs.size < INSPECTION_JOB_LIMIT) return;
  const completed = [...inspectionJobs.values()]
    .filter(job => job.status !== 'running')
    .sort((left, right) => Number(left.finishedAt || 0) - Number(right.finishedAt || 0));
  while (inspectionJobs.size >= INSPECTION_JOB_LIMIT && completed.length) {
    inspectionJobs.delete(completed.shift().jobId);
  }
}

function hasRunningInspectionJob(type) {
  cleanupInspectionJobs();
  return [...inspectionJobs.values()].some(job => job.type === type && job.status === 'running');
}

function createInspectionJob(type) {
  cleanupInspectionJobs();
  if (inspectionJobs.size >= INSPECTION_JOB_LIMIT) return null;
  const jobId = `${type}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const job = {
    jobId,
    type,
    status: 'running',
    targetTotal: 0,
    completed: 0,
    trafficSkipped: 0,
    networkChecked: 0,
    normal: 0,
    abnormal: 0,
    recovered: 0,
    createdAt: Date.now(),
    updatedAt: Date.now()
  };
  inspectionJobs.set(jobId, job);
  return job;
}

function updateInspectionJob(jobId, progress = {}) {
  const job = inspectionJobs.get(jobId);
  if (!job || job.status !== 'running') return;
  const allowed = ['targetTotal', 'completed', 'trafficSkipped', 'networkChecked', 'normal', 'abnormal', 'recovered'];
  for (const key of allowed) {
    if (Number.isFinite(Number(progress[key]))) job[key] = Number(progress[key]);
  }
  job.updatedAt = Date.now();
}

function reportSummary(report = {}) {
  const summary = {};
  for (const [key, value] of Object.entries(report)) {
    if (key === 'results' || key === 'alert_summary') continue;
    summary[key] = value;
  }
  return summary;
}

function finalJobProgress(type, report) {
  if (type === 'backlink') {
    return {
      targetTotal: report.target_total,
      completed: report.completed,
      trafficSkipped: report.traffic_skipped,
      networkChecked: report.network_checked,
      normal: report.normal,
      abnormal: Number(report.network_checked || 0) - Number(report.normal || 0) - Number(report.recovered || 0),
      recovered: report.recovered
    };
  }
  return {
    targetTotal: report.target_total,
    completed: report.completed,
    normal: report.normal,
    abnormal: Number(report.first_failure || 0) + Number(report.ongoing_failure || 0)
      + Number(report.reached_dead || 0) + Number(report.task_errors || 0),
    recovered: report.recovered
  };
}

function startInspectionJob(type, label, worker) {
  const job = createInspectionJob(type);
  if (!job) return null;
  const task = runTrackedJob(label, async () => {
    try {
      const report = await worker(progress => updateInspectionJob(job.jobId, progress));
      if (!report?.started) throw new Error(report?.reason || '任务未能启动');
      updateInspectionJob(job.jobId, finalJobProgress(type, report));
      job.status = 'completed';
      job.summary = reportSummary(report);
      job.finishedAt = Date.now();
      job.updatedAt = job.finishedAt;
      return report;
    } catch (error) {
      job.status = 'failed';
      job.error = safeApiErrorMessage(error, '巡检任务执行失败');
      job.finishedAt = Date.now();
      job.updatedAt = job.finishedAt;
      throw error;
    }
  });
  if (!task) {
    inspectionJobs.delete(job.jobId);
    return null;
  }
  return job;
}

function publicInspectionJob(job) {
  return {
    jobId: job.jobId,
    type: job.type,
    status: job.status,
    targetTotal: job.targetTotal,
    completed: job.completed,
    trafficSkipped: job.trafficSkipped,
    networkChecked: job.networkChecked,
    normal: job.normal,
    abnormal: job.abnormal,
    recovered: job.recovered,
    summary: job.summary || null,
    error: job.error || null,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    finishedAt: job.finishedAt || null
  };
}

function normalizeGenericAnalyticsCode(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.length > 12 * 1024) throw new Error('自定义统计代码不能超过 12KB');
  if (/<iframe\b|document\s*\.\s*write(?:ln)?\s*\(|createElement\s*\(\s*['\"]iframe/i.test(raw)) {
    throw new Error('自定义统计代码不允许 iframe 或 document.write');
  }
  if (/<script\b[^>]*\son\w+\s*=/i.test(raw)) throw new Error('自定义统计代码不允许脚本事件属性');

  const scriptOnly = raw.replace(/<!--[\s\S]*?-->/g, '').trim();
  const remainder = scriptOnly.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, '').trim();
  if (remainder || !/<script\b/i.test(scriptOnly)) {
    throw new Error('自定义统计代码只能包含一个或多个 <script> 标签');
  }
  return raw;
}

async function analyticsConfig() {
  return SystemModel.getConfigValues(ANALYTICS_CONFIG_KEYS);
}

async function login(req, res) {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    if (!username || !password) return fail(res, '请输入用户名和密码');
    const admin = await SystemModel.getAdminByUsername(username);
    if (!admin || !(await bcrypt.compare(password, admin.password_hash))) return fail(res, '用户名或密码错误', 401);
    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: 'admin', type: 'admin' },
      ADMIN_JWT_SECRET,
      { expiresIn: '8h', algorithm: 'HS256' }
    );
    return ok(res, { token, expiresIn: 28800 }, '登录成功');
  } catch {
    return fail(res, '登录服务异常', 500);
  }
}

async function changePassword(req, res) {
  try {
    const oldPassword = typeof req.body?.oldPassword === 'string' ? req.body.oldPassword : '';
    const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
    if (!oldPassword || !newPassword) return fail(res, '请输入原密码和新密码');
    if (newPassword.length < 8) return fail(res, '新密码长度不得少于 8 位');
    if (newPassword.length > 128) return fail(res, '新密码长度不得超过 128 位');

    const admin = await SystemModel.getAdminByUsername(req.admin.username, 'password');
    if (!admin || !(await bcrypt.compare(oldPassword, admin.password_hash))) return fail(res, '原密码不正确', 403);
    const passwordHash = await bcrypt.hash(newPassword, 12);
    const updated = await SystemModel.updateAdminPassword(admin.id, passwordHash);
    if (!updated.changes) return fail(res, '管理员账号不存在', 404);
    return ok(res, null, '密码修改成功，请重新登录');
  } catch (error) {
    console.error('修改管理员密码失败：', error);
    return fail(res, safeApiErrorMessage(error), 500);
  }
}

async function getAnalyticsConfig(req, res) {
  try { return ok(res, await analyticsConfig()); }
  catch { return fail(res, '获取统计配置失败', 500); }
}

async function saveAnalyticsConfig(req, res) {
  try {
    const body = req.body || {};
    const values = {};
    for (const key of ANALYTICS_CONFIG_KEYS) {
      let value = String(body[key] ?? '').trim();
      if (key === 'umami_script_url' && value) {
        value = normalizeAnalyticsScriptUrl(value);
      }
      if (key === 'generic_analytics_code') value = normalizeGenericAnalyticsCode(value);
      if (ANALYTICS_ENABLED_KEYS.has(key)) {
        value = ['1', 'true', 'on'].includes(value.toLowerCase()) ? '1' : '0';
      }
      values[key] = value;
    }

    if (values.umami_enabled === '1' && !values.umami_website_id) {
      return fail(res, '启用 Umami 前请填写 Website ID');
    }
    if (values.cf_analytics_enabled === '1' && !values.cf_beacon_token) {
      return fail(res, '启用 Cloudflare Web Analytics 前请填写 Beacon Token');
    }
    if (values.clarity_enabled === '1' && !/^[a-z0-9_-]{4,100}$/i.test(values.clarity_project_id)) {
      return fail(res, '请输入有效的 Microsoft Clarity Project ID');
    }
    if (values.generic_analytics_enabled === '1' && !values.generic_analytics_code) {
      return fail(res, '启用通用统计前请粘贴完整的 <script> 统计代码');
    }

    // 始终完整写入五项配置：复选框未勾选时也要可靠保存为 0，避免前端
    // FormData 省略未勾选字段后留下旧状态。
    const entries = ANALYTICS_CONFIG_KEYS.map(key => [key, values[key]]);
    await SystemModel.upsertConfigs(entries);
    return ok(res, await analyticsConfig(), '第三方统计设置已保存');
  } catch (error) {
    console.error('保存统计配置失败：', error);
    if (error instanceof TypeError || /(脚本地址|自定义统计代码)/.test(String(error?.message || ''))) {
      return fail(res, error.message || '统计脚本配置格式不正确');
    }
    return fail(res, safeApiErrorMessage(error), 500);
  }
}

async function getSettings(req, res) {
  try {
    const settings = await SystemModel.getAllConfig();
    // Device Key 从不回显到浏览器；空值保存时由 saveSettings 保留现有密钥。
    settings.bark_device_key_configured = Boolean(String(settings.bark_device_key || '').trim());
    settings.bark_device_key = '';
    return ok(res, settings);
  }
  catch { return fail(res, '获取系统设置失败', 500); }
}

async function getRiskControlSettings(req, res) {
  try { return ok(res, await SystemModel.getRiskControlConfig()); }
  catch { return fail(res, '获取站点风控监控参数失败', 500); }
}

async function saveSettings(req, res) {
  try {
    const body = req.body || {};
    const entries = [];
    const currentBarkKey = await SystemModel.configValue('bark_device_key');
    const barkEnabled = body.bark_enabled === undefined
      ? String(await SystemModel.configValue('bark_enabled')) === '1'
      : ['1', 'true', 'on'].includes(String(body.bark_enabled).toLowerCase());
    const barkDeviceKey = String(body.bark_device_key || '').trim() || String(currentBarkKey || '').trim();
    const barkServerUrl = String(body.bark_server_url === undefined
      ? await SystemModel.configValue('bark_server_url') : body.bark_server_url).trim();
    if (barkEnabled && (!barkDeviceKey || !barkServerUrl)) return fail(res, '启用 Bark 前请填写服务地址和 Device Key');
    if (barkEnabled) {
      const parsedBarkUrl = new URL(barkServerUrl);
      if (parsedBarkUrl.protocol !== 'https:') return fail(res, 'Bark 服务地址必须使用 HTTPS');
    }
    for (const key of Object.keys(SystemModel.CONFIG_DEFAULTS)) {
      if (body[key] === undefined) continue;
      let value = String(body[key]).trim();
      if (key === 'bark_device_key') {
        // 空输入代表“不修改”，显式清除才会删掉已保存的 Device Key。
        if (!value && !['1', 'true', 'on'].includes(String(body.bark_device_key_clear || '').toLowerCase())) continue;
        if (value.length > 300) return fail(res, 'Bark Device Key 长度不合法');
      }
      if (key === 'auto_approve_threshold') {
        const number = Number.parseInt(value, 10);
        if (!Number.isInteger(number) || number < 1 || number > 100000) return fail(res, '自动审核阈值必须是 1 到 100000 的整数');
        value = String(number);
      }
      if (['min_interaction_rate', 'min_attributed_interaction_rate', 'max_hourly_burst_ratio', 'empty_referer_threshold'].includes(key)) {
        const number = Number(value);
        if (!Number.isFinite(number) || number < 0 || number > 1) {
          return fail(res, `${key} 必须是 0 到 1 之间的数值`);
        }
        value = String(number);
      }
      if (key === 'pv_uv_ratio_threshold') {
        const number = Number(value);
        if (!Number.isFinite(number) || number <= 0 || number > 100000) {
          return fail(res, 'PV/UV 异常比值阈值必须是大于 0 且不超过 100000 的数值');
        }
        value = String(number);
      }
      if (key === 'site_url') value = normalizeUrl(value);
      if (key === 'publish_url' && value) value = normalizeUrl(value);
      if (key === 'webhook_url' && value) value = normalizeUrl(value);
      if (key === 'bark_server_url' && value) {
        value = normalizeUrl(value);
        if (new URL(value).protocol !== 'https:') return fail(res, 'Bark 服务地址必须使用 HTTPS');
      }
      if (key === 'bark_enabled') value = ['1', 'true', 'on'].includes(value.toLowerCase()) ? '1' : '0';
      if (key === 'site_logo_url' && value) {
        if (value.startsWith('/uploads/logo/')) {
          if (!/^\/uploads\/logo\/[a-zA-Z0-9._-]+$/.test(value)) return fail(res, 'Logo 本地地址无效');
        } else {
          value = normalizeUrl(value);
        }
      }
      if (['csv_url_partners', 'csv_url_ads', 'csv_url_mirrors'].includes(key) && value) {
        value = normalizeUrl(value);
        const parsed = new URL(value);
        if (!['http:', 'https:'].includes(parsed.protocol)) return fail(res, 'CSV 数据源仅支持 HTTP/HTTPS 地址');
      }
      if (['contact_email', 'lost_prevention_email'].includes(key)
        && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return fail(res, '防失联官方邮箱格式不正确');
      if (key === 'publish_modal_enabled') value = ['1', 'true', 'on'].includes(value.toLowerCase()) ? '1' : '0';
      if (['site_name', 'site_url', 'auto_approve_threshold'].includes(key) && !value) return fail(res, '配置内容不能为空');
      entries.push([key, value]);
    }
    await SystemModel.upsertConfigs(entries);
    CacheService.clearPublicCache();
    require('./PublicController').clearMirrorsCache();
    return ok(res, null, '系统设置已保存');
  } catch (error) {
    console.error('保存系统设置失败：', error);
    return fail(res, safeApiErrorMessage(error), 500);
  }
}

function healthStatus(summary, configured) {
  if (!configured) return 'unconfigured';
  if (Number(summary.lastFailureStatusCode) === 401 || Number(summary.lastFailureStatusCode) === 403) return 'auth_error';
  if (Number(summary.consecutiveFailures || 0) >= 3) return 'offline';
  if (Number(summary.consecutiveFailures || 0) > 0) return 'degraded';
  return summary.lastSuccessAt ? 'healthy' : 'untested';
}

async function readWebhookHealth() {
  const [webhookUrl, barkEnabled, barkDeviceKey] = await Promise.all([
    SystemModel.configValue('webhook_url'),
    SystemModel.configValue('bark_enabled'),
    SystemModel.configValue('bark_device_key')
  ]);
  const primaryProvider = providerForUrl(webhookUrl);
  const health = await WebhookDeliveryModel.getHealth(primaryProvider);
  const primaryConfigured = Boolean(primaryProvider);
  const barkConfigured = String(barkEnabled) === '1' && Boolean(String(barkDeviceKey || '').trim());
  return {
    primary: { provider: primaryProvider || 'none', configured: primaryConfigured,
      status: healthStatus(health.primary, primaryConfigured), ...health.primary },
    backup: { provider: 'bark', configured: barkConfigured,
      status: healthStatus(health.bark, barkConfigured), ...health.bark },
    lastFallbackAt: health.lastFallbackAt
  };
}

async function getWebhookHealth(req, res) {
  try { return ok(res, await readWebhookHealth()); }
  catch (error) { return fail(res, safeApiErrorMessage(error, '获取告警通道状态失败'), 500); }
}

async function listWebhookDeliveries(req, res) {
  try { return ok(res, { deliveries: await WebhookDeliveryModel.listDeliveries(req.query?.limit) }); }
  catch (error) { return fail(res, safeApiErrorMessage(error, '获取告警投递记录失败'), 500); }
}

async function uploadSiteLogo(req, res) {
  try {
    if (!req.file) return fail(res, '请选择 PNG、JPG 或 WebP 格式的 Logo（最大 2MB）');
    const siteLogoUrl = `/uploads/logo/${req.file.filename}`;
    await SystemModel.upsertConfig('site_logo_url', siteLogoUrl);
    CacheService.clearPublicCache();
    require('./PublicController').clearMirrorsCache();
    return ok(res, { site_logo_url: siteLogoUrl }, 'Logo 上传成功');
  } catch (error) {
    console.error('上传站点 Logo 失败：', error);
    return fail(res, safeApiErrorMessage(error), 500);
  }
}

async function testWebhook(req, res) {
  const result = await sendAdminAlert(
    '🔔 Webhook 测试消息',
    `> **状态：** 主告警通道测试\n> **测试时间：** ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`,
    { eventType: 'manual_test_primary', allowBarkFallback: false }
  );
  if (!result.sent) {
    return fail(
      res,
      result.reason === '未配置 Webhook' ? '请先保存管理员告警 Webhook 地址' : `测试消息发送失败：${result.reason}`
    );
  }
  return ok(res, { result, health: await readWebhookHealth() }, '主告警通道测试消息已发送');
}

async function testBark(req, res) {
  const result = await sendBarkTestAlert(
    '📱 Bark 测试消息',
    `> **状态：** Bark 备用告警通道测试\n> **测试时间：** ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`,
    { eventType: 'manual_test_bark' }
  );
  if (!result.sent) return fail(res, `Bark 测试消息发送失败：${result.reason || '未知错误'}`);
  return ok(res, { result, health: await readWebhookHealth() }, 'Bark 测试消息已发送');
}

async function getReview(req, res) {
  try {
    const threshold = Math.max(1, Number.parseInt(await SystemModel.configValue('auto_approve_threshold'), 10) || 10);
    const rows = await PartnerModel.listReviewPartners();
    return ok(res, { threshold, count: rows.length, partners: rows });
  } catch {
    return fail(res, '获取待审核友链失败', 500);
  }
}

async function getOverview(req, res) {
  try {
    const [total, partnerStats] = await Promise.all([
      LogModel.getOverviewTraffic(),
      PartnerModel.getOverviewPartnerStats()
    ]);
    const { active, leader, clicks } = partnerStats;
    return ok(res, {
      todayIp: total.value,
      activePartners: active.value,
      outflowClicks: clicks.value,
      roi: Number((clicks.value / (total.value + 1)).toFixed(3)),
      leader: leader || null
    });
  } catch {
    return fail(res, '获取仪表盘数据失败', 500);
  }
}

async function getDashboardStats(req, res) {
  try {
    const [todayExchange, todayLeader, partnerStats, newPartnerCounts, newPartnerTraffic, partners, todaySiteTraffic] = await Promise.all([
      LogModel.getTodayExchange(),
      LogModel.getTodayTrafficLeader(),
      PartnerModel.getOverviewPartnerStats(),
      PartnerModel.getNewPartnerCounts(),
      LogModel.getNewPartnerTraffic(),
      LogModel.listRiskPartnerMetrics(),
      SiteTrafficService.getTodaySummary()
    ]);
    const riskCandidates = partners.filter(item => Number(item.score_24h || 0) >= 30);
    const riskResults = await runPromisePool(riskCandidates, 3, candidate => RiskService.analyzePartner(candidate.id, { includeClients: false }), 15000);
    const suspiciousPartners = riskResults
      .filter(result => result.status === 'fulfilled' && result.value?.risk?.alertable)
      .map(result => {
        const report = result.value;
        return {
          id: report.partner.id,
          name: report.partner.name,
          domain: report.partner.domain,
          score_24h: report.uv24h,
          pv_24h: report.pv24h,
          risk_level: report.risk.level,
          risk_reasons: report.risk.reasons
        };
      })
      .sort((a, b) => b.score_24h - a.score_24h || b.pv_24h - a.pv_24h);

    const inboundCount = Number(todayExchange.inbound?.count || 0);
    const outboundCount = Number(todayExchange.outbound?.count || 0);
    return ok(res, {
      todayInbound: inboundCount,
      todayOutbound: outboundCount,
      today_inflow_uv: inboundCount,
      today_outflow_uv: outboundCount,
      active_partners: Number(partnerStats.active?.value || 0),
      today_leader: todayLeader || null,
      new_partners_24h: newPartnerCounts.last24h.value,
      new_partners_24h_today_uv: newPartnerTraffic.last24h.value,
      new_partners_7d: newPartnerCounts.last7d.value,
      new_partners_7d_total_uv: newPartnerTraffic.last7d.value,
      today_site_traffic: todaySiteTraffic,
      suspicious_partners: suspiciousPartners
    });
  } catch (error) {
    console.error('仪表盘统计失败：', error.message);
    return fail(res, '获取仪表盘统计失败', 500);
  }
}

async function getSiteTrafficTrend(req, res) {
  try {
    return ok(res, await SiteTrafficService.getTrend(String(req.query.range || '7d')));
  } catch (error) {
    console.error('全站访客趋势查询失败：', error.message);
    return fail(res, '获取全站访客趋势失败', 500);
  }
}

async function getPartners(req, res) {
  try { return ok(res, await PartnerModel.listAdminPartners(String(req.query.q || '').trim())); }
  catch { return fail(res, '获取友链管理数据失败', 500); }
}

async function getPartnerAnalytics(req, res) {
  try {
    // Webhook 定时扫描与后台弹窗复用同一份指标计算，避免诊断口径漂移。
    const report = await RiskService.analyzePartner(Number(req.params.id));
    if (!report) return fail(res, '友链不存在', 404);
    return ok(res, report);

    const partner = await PartnerModel.findAnalyticsPartner(Number(req.params.id));
    if (!partner) return fail(res, '友链不存在', 404);
    const [{ summary, inflowLogs, requestRows, interaction, hourlyPeak }, thresholds] = await Promise.all([
      LogModel.getPartnerAnalytics(partner.id),
      SystemModel.getRiskControlConfig()
    ]);
    const requestMap = new Map(requestRows.map(row => [row.ip, row]));
    const pv = Number(summary.pv || 0);
    const uv = Number(summary.uv || inflowLogs.length || 0);
    const pvUvRatio = uv ? Number((pv / uv).toFixed(2)) : 0;
    const clientName = parsed => {
      const os = [parsed.os.name, parsed.os.version].filter(Boolean).join(' ');
      const browserVersion = parsed.browser.major || String(parsed.browser.version || '').split('.')[0];
      const browser = [parsed.browser.name, browserVersion].filter(Boolean).join(' ');
      return [os || '未知系统', browser || '未知浏览器'].join(' · ');
    };
    const normalizeType = parsed => parsed.device.type === 'mobile' ? '手机'
      : parsed.device.type === 'tablet' ? '平板' : '电脑';
    const countStats = new Map();
    const osStatsMap = new Map();
    const browserStatsMap = new Map();
    const allInflowIps = inflowLogs.map(log => {
      const parsed = new UAParser(log.user_agent || '').getResult();
      const deviceType = normalizeType(parsed);
      const osName = parsed.os.name || '未知系统';
      const browserName = parsed.browser.name || '未知浏览器';
      countStats.set(deviceType, (countStats.get(deviceType) || 0) + 1);
      osStatsMap.set(osName, (osStatsMap.get(osName) || 0) + 1);
      browserStatsMap.set(browserName, (browserStatsMap.get(browserName) || 0) + 1);
      const requests = Number(requestMap.get(log.ip)?.requests || 1);
      const client = clientName(parsed);
      return {
        ip: log.ip,
        client,
        device_model: client,
        device_type: deviceType,
        timestamp: log.timestamp,
        requests,
        ratio: pv ? Number((requests * 100 / pv).toFixed(1)) : 0
      };
    });
    const statistic = (map, names, limit = 10) => names
      .map(name => ({
        name,
        count: map.get(name) || 0,
        ratio: inflowLogs.length ? Number(((map.get(name) || 0) * 100 / inflowLogs.length).toFixed(1)) : 0
      }))
      .concat([...map.entries()]
        .filter(([name]) => !names.includes(name))
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({
          name,
          count,
          ratio: inflowLogs.length ? Number((count * 100 / inflowLogs.length).toFixed(1)) : 0
        })))
      .slice(0, limit);
    const deviceTypeStats = statistic(countStats, ['电脑', '手机', '平板'], 3);
    const osStats = statistic(osStatsMap, [], 10);
    const browsers = statistic(browserStatsMap, [], 10);
    const topIps = [...allInflowIps]
      .sort((a, b) => b.requests - a.requests || String(b.timestamp).localeCompare(String(a.timestamp)))
      .slice(0, 10);
    const maxIpRatio = topIps[0]?.ratio || 0;
    const interactedUv = Number(interaction?.interacted_uv || 0);
    const interactionRate = uv ? Number((interactedUv / uv).toFixed(4)) : 0;
    const peakHourlyUv = Number(hourlyPeak?.peak_hourly_uv || 0);
    const peakHourlyRatio = uv ? Number((peakHourlyUv / uv).toFixed(4)) : 0;
    const refererObserved = Number(summary.referer_observed || 0);
    const emptyRefererCount = Number(summary.empty_referer_count || 0);
    const emptyRefererRatio = refererObserved
      ? Number((emptyRefererCount / refererObserved).toFixed(4))
      : 0;
    const diagnostics = {
      zero_conversion: uv > 100 && interactionRate < thresholds.min_interaction_rate,
      interaction_rate: interactionRate,
      interacted_uv: interactedUv,
      time_burst: uv > 50 && peakHourlyRatio > thresholds.max_hourly_burst_ratio,
      peak_hourly_ratio: peakHourlyRatio,
      peak_hourly_uv: peakHourlyUv,
      empty_referer: refererObserved > 0 && emptyRefererRatio > thresholds.empty_referer_threshold,
      empty_referer_ratio: emptyRefererRatio,
      referer_observed: refererObserved,
      pv_uv_anomaly: pvUvRatio > thresholds.pv_uv_ratio_threshold,
      pv_uv_ratio: pvUvRatio,
      thresholds
    };
    return ok(res, {
      partner,
      pv24h: pv,
      uv24h: uv,
      pvUvRatio,
      outflowClicks: partner.outflow_clicks,
      roi: Number((partner.outflow_clicks / (uv + 1)).toFixed(3)),
      complianceRate: Number(summary.compliance_rate || 0),
      device_type_stats: deviceTypeStats,
      os_stats: osStats,
      inflow_ips: allInflowIps,
      all_inflow_ips: allInflowIps,
      operatingSystems: osStats,
      browsers,
      topIps,
      diagnostics,
      warnings: {
        pvUvHigh: diagnostics.pv_uv_anomaly,
        singleIpHigh: maxIpRatio > 30,
        zeroConversion: diagnostics.zero_conversion,
        timeBurst: diagnostics.time_burst,
        emptyReferer: diagnostics.empty_referer
      }
    });
  } catch (error) {
    console.error('风控分析失败：', error.message);
    return fail(res, '获取站点分析失败', 500);
  }
}

async function createPartner(req, res) {
  try {
    const { name, url, category, backlink_url, contact, description, is_exempt, ping_exempt } = req.body || {};
    if (![name, url, category].every(value => String(value || '').trim())) return fail(res, '请完整填写网站名称、网站地址和分类');
    const { url: cleanUrl, domain: cleanDomain } = normalizePartnerUrl(url);
    const backlinkUrl = String(backlink_url || '').trim();
    const cleanContact = String(contact || '').trim();
    const cleanDescription = String(description || '').trim();
    if (cleanContact.length > 200) return fail(res, '站长联系方式长度不能超过 200 个字符');
    if (cleanDescription.length > 200) return fail(res, '简易描述长度不能超过 200 个字符');
    const result = await PartnerModel.createApprovedPartner({
      name: String(name).trim(),
      domain: cleanDomain,
      url: cleanUrl,
      category: String(category).trim(),
      backlinkUrl: backlinkUrl ? normalizeUrl(backlinkUrl) : null,
      contact: cleanContact,
      description: cleanDescription,
      isExempt: [true, 1, '1', 'true', 'on'].includes(is_exempt),
      pingExempt: [true, 1, '1', 'true', 'on'].includes(ping_exempt)
    });
    CacheService.clearPublicCache();
    return ok(res, { id: result.id }, '友链已新增');
  } catch (error) {
    console.error('新增友链失败：', error);
    if (isUniqueConstraintError(error)) return fail(res, '该来源域名已存在', 409);
    return fail(res, safeApiErrorMessage(error), 500);
  }
}

async function updatePartner(req, res) {
  try {
    const id = Number(req.params.id);
    const body = req.body || {};
    if (!Number.isInteger(id)) return fail(res, '友链编号不合法');
    const changes = {};
    const textField = (key, label, max = 200, targetKey = key) => {
      if (body[key] === undefined) return;
      const value = String(body[key]).trim();
      if (!value && ['name', 'category'].includes(key)) throw new Error(`${label}不能为空`);
      if (value.length > max) throw new Error(`${label}长度不能超过 ${max} 个字符`);
      changes[targetKey] = value;
    };
    textField('name', '站点名称', 80);
    textField('category', '所属分类', 50);
    textField('description', '简易描述', 200);
    textField('contact', '站长联系方式', 200);
    if (body.contact === undefined && body.contact_info !== undefined) {
      textField('contact_info', '站长联系方式', 200, 'contact');
    }
    if (body.url !== undefined) {
      const { url: cleanUrl, domain: cleanDomain } = normalizePartnerUrl(body.url);
      changes.url = cleanUrl;
      changes.domain = cleanDomain;
    } else if (body.domain !== undefined) {
      const { domain } = normalizePartnerUrl(body.domain);
      changes.domain = domain;
    }
    if (body.backlink_url !== undefined) {
      const backlinkUrl = String(body.backlink_url || '').trim();
      changes.backlink_url = backlinkUrl ? normalizeUrl(backlinkUrl) : null;
    }
    if (body.priority !== undefined) {
      const priority = Number(body.priority);
      if (!Number.isInteger(priority) || priority < 0 || priority > 999999) return fail(res, '置顶权重必须是 0 到 999999 的整数');
      changes.priority = priority;
    }
    if (body.is_exempt !== undefined) {
      changes.is_exempt = [true, 1, '1', 'true', 'on'].includes(body.is_exempt) ? 1 : 0;
    }
    if (body.ping_exempt !== undefined) {
      changes.ping_exempt = [true, 1, '1', 'true', 'on'].includes(body.ping_exempt) ? 1 : 0;
    }
    if (!Object.keys(changes).length) return fail(res, '没有可修改的字段');
    const result = await PartnerModel.updatePartner(id, changes);
    if (!result.changes) return fail(res, '友链不存在', 404);
    CacheService.clearPublicCache();
    return ok(res, null, '修改成功');
  } catch (error) {
    console.error('修改友链失败：', error);
    if (isUniqueConstraintError(error)) return fail(res, '该来源域名已存在', 409);
    return fail(res, safeApiErrorMessage(error), 500);
  }
}

async function updatePartnerApproval(req, res) {
  try {
    const id = Number(req.params.id);
    const { is_approved } = req.body || {};
    if (!Number.isInteger(id) || ![0, 1, 2].includes(Number(is_approved))) return fail(res, '参数不合法');
    const result = await PartnerModel.updateApproval(id, Number(is_approved));
    if (!result.changes) return fail(res, '友链不存在', 404);
    CacheService.clearPublicCache();
    return ok(
      res,
      null,
      Number(is_approved) === 1 ? '已审核通过' : Number(is_approved) === 2 ? '已拒绝友链' : '已设为待审核'
    );
  } catch {
    return fail(res, '更新友链状态失败', 500);
  }
}

async function whitelistPartner(req, res) {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return fail(res, '友链编号不合法');
    const result = await PartnerModel.whitelistPartner(id);
    if (!result.changes) return fail(res, '友链不存在', 404);
    CacheService.clearPublicCache();
    return ok(res, { id, is_whitelisted: 1 }, '已加入风控白名单');
  } catch (error) {
    console.error('加入风控白名单失败：', error);
    return fail(res, safeApiErrorMessage(error, '加入风控白名单失败'), 500);
  }
}

async function clearPartnerTraffic(req, res) {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return fail(res, '友链编号不合法');
    const partner = await PartnerModel.findAnalyticsPartner(id);
    if (!partner) return fail(res, '友链不存在', 404);
    const deleted = await LogModel.clearPartnerTraffic(id);
    CacheService.clearPublicCache();
    return ok(res, deleted, '该站点流量数据已清空');
  } catch (error) {
    console.error('清空站点流量失败：', error);
    return fail(res, safeApiErrorMessage(error, '清空站点流量失败'), 500);
  }
}

async function deletePartner(req, res) {
  try {
    const result = await PartnerModel.deletePartner(Number(req.params.id));
    if (!result.changes) return fail(res, '友链不存在', 404);
    CacheService.clearPublicCache();
    return ok(res, null, '友链已删除');
  } catch {
    return fail(res, '删除友链失败', 500);
  }
}

async function regeneratePartnerSourceSid(req, res) {
  try {
    const id = Number.parseInt(String(req.params.id || ''), 10);
    if (!Number.isSafeInteger(id) || id <= 0) return fail(res, '友链编号不合法');
    const token = await SourceTokenModel.rotatePartnerSid(id);
    if (!token) return fail(res, '友链不存在', 404);
    const sourceUrls = buildSourceEntryUrls(token.sid, await SystemModel.configValue('site_url'));
    return ok(res, {
      source_sid: token.sid,
      source_links: { path: sourceUrls.pathUrl, query: sourceUrls.queryUrl }
    }, '新的来路识别标记已生成，原标记仍然有效');
  } catch (error) {
    console.error('重新生成来路识别标记失败：', error);
    return fail(res, safeApiErrorMessage(error, '重新生成失败'), 500);
  }
}

function checkAllLinks(req, res) {
  if (InspectionService.isBacklinkCheckInProgress() || hasRunningInspectionJob('backlink')) {
    return fail(res, '反向友链巡检正在执行，请稍后再试', 409);
  }
  const job = startInspectionJob('backlink', '后台手动全量反向友链巡检', onProgress => (
    InspectionService.checkAllBacklinks({
      mode: 'manual',
      skipRecentTraffic: true,
      includeDeepDead: true,
      sendAdminAlert,
      aggregateAlerts: true,
      alwaysSendSummary: true,
      includeAllResultsInSummary: true,
      alertTaskLabel: '后台手动反链全查',
      onDataChanged: CacheService.clearPublicCache,
      onProgress
    })
  ));
  if (!job) return fail(res, '服务正在停止或任务队列已满，暂时无法启动巡检', 503);
  return res.status(202).json({
    code: 200,
    msg: '已在后台启动全量反向友链巡检',
    data: publicInspectionJob(job)
  });
}

async function checkLink(req, res) {
  const controller = new AbortController();
  const timeoutError = Object.assign(new Error('反链巡检超过 15 秒'), { code: 'TASK_TIMEOUT' });
  const timeoutId = setTimeout(() => controller.abort(timeoutError), 15000);
  try {
    const link = await PartnerModel.findBacklinkPartner(Number(req.params.id));
    if (!link) return fail(res, '友链不存在', 404);
    const myMainDomain = parseHostname(await SystemModel.configValue('site_url'));
    if (!myMainDomain) return fail(res, '本站地址配置无效，无法进行反链巡检');
    const result = await InspectionService.checkSingleBacklink(
      link,
      myMainDomain,
      await SystemModel.configValue('site_name'),
      {
        signal: controller.signal,
        aggregateAlerts: true,
        onDataChanged: CacheService.clearPublicCache
      }
    );
    result.checked_at = result.checked_at || new Date().toISOString();
    result.result_text = result.result_text || backlinkResultMessage(result);
    if (result.alert_event) {
      await InspectionAlertService.sendSingleBacklinkResult(link, result, sendAdminAlert);
    }
    return ok(res, result, backlinkResultMessage(result));
  } catch (error) {
    console.error('反链巡检失败：', error);
    return fail(res, safeApiErrorMessage(error, '反链巡检失败'), 500);
  } finally {
    clearTimeout(timeoutId);
  }
}

function runInspectionWithTimeout(message, worker) {
  const controller = new AbortController();
  const timeoutError = Object.assign(new Error(message), { code: 'TASK_TIMEOUT' });
  const timeoutId = setTimeout(() => controller.abort(timeoutError), 15000);
  return Promise.resolve()
    .then(() => worker(controller.signal))
    .finally(() => clearTimeout(timeoutId));
}

async function inspectLink(req, res) {
  try {
    const id = Number.parseInt(String(req.params.id || ''), 10);
    if (!Number.isSafeInteger(id) || id <= 0) return fail(res, '友链编号不合法');

    const [link, siteUrl, siteName] = await Promise.all([
      PartnerModel.findCombinedInspectionPartner(id),
      SystemModel.configValue('site_url'),
      SystemModel.configValue('site_name')
    ]);
    if (!link) return fail(res, '友链不存在、未审核或已删除', 404);

    const myMainDomain = parseHostname(siteUrl);
    const [backlinkSettled, pingSettled] = await Promise.allSettled([
      runInspectionWithTimeout('反链巡检超过 15 秒', signal => {
        if (!myMainDomain && Number(link.is_exempt) !== 1) {
          throw Object.assign(new Error('本站地址配置无效，无法进行反链巡检'), { code: 'CONFIG' });
        }
        return InspectionService.checkSingleBacklink(link, myMainDomain, siteName, { signal });
      }),
      runInspectionWithTimeout('站点探活超过 15 秒', signal => PingService.pingSingleLink(link, { signal }))
    ]);

    // 两个服务各自完成短写入后再统一清缓存，避免并行任务重复刷新公共缓存。
    CacheService.clearPublicCache();
    const rejected = [backlinkSettled, pingSettled].find(item => item.status === 'rejected');
    if (rejected) throw rejected.reason;

    const checkedAt = new Date().toISOString();
    const backlink = {
      ...backlinkSettled.value,
      checked_at: backlinkSettled.value.checked_at || checkedAt,
      result_text: backlinkSettled.value.result_text || backlinkResultMessage(backlinkSettled.value)
    };
    const connectivity = {
      ...pingSettled.value,
      checked_at: pingSettled.value.checked_at || pingSettled.value.last_ping_at || checkedAt,
      healthy: pingSettled.value.ping_status === 'ok' && !pingSettled.value.error,
      result_text: pingSettled.value.result_text || pingResultMessage(pingSettled.value)
    };
    const result = { partner_id: link.id, checked_at: checkedAt, backlink, connectivity };

    if (backlink.alert_event || connectivity.alert_event) {
      await InspectionAlertService.sendCombinedSingleResult(link, result, sendAdminAlert);
    }
    return ok(res, result, '单站联合检测完成');
  } catch (error) {
    console.error('单站联合检测失败：', error);
    return fail(res, safeApiErrorMessage(error, '单站联合检测失败'), 500);
  }
}

async function checkLinkHealth(req, res) {
  const controller = new AbortController();
  const timeoutError = Object.assign(new Error('站点探活超过 15 秒'), { code: 'TASK_TIMEOUT' });
  const timeoutId = setTimeout(() => controller.abort(timeoutError), 15000);
  try {
    const id = Number.parseInt(String(req.params.id || ''), 10);
    if (!Number.isSafeInteger(id) || id <= 0) return fail(res, '友链编号不合法');
    const link = await PartnerModel.findPingPartner(id);
    if (!link) return fail(res, '友链不存在、未审核或已删除', 404);
    const result = await PingService.pingSingleLink(link, {
      signal: controller.signal,
      onDataChanged: CacheService.clearPublicCache,
      aggregateAlerts: true
    });
    result.checked_at = result.checked_at || result.last_ping_at || new Date().toISOString();
    result.result_text = result.result_text || pingResultMessage(result);
    if (result.alert_event) {
      await InspectionAlertService.sendSinglePingResult(link, result, sendAdminAlert);
    }
    return ok(res, { ...result, healthy: !result.error }, pingResultMessage(result));
  } catch (error) {
    console.error('友链健康探测失败：', error);
    return fail(res, safeApiErrorMessage(error, '友链健康探测失败'), 500);
  } finally {
    clearTimeout(timeoutId);
  }
}

function backlinkResultMessage(result = {}) {
  if (result.exempted) return '免检站点，未执行巡检';
  if (result.backlink_status === 'protected') return '防护页拦截，暂时无法判断';
  if (result.alert_event === 'backlink_recovered') return '已恢复反链';
  if (result.alert_event === 'backlink_lost') return '确认掉链';
  if (result.alert_event === 'backlink_first_unreachable') return '首次网络异常（1/3）';
  if (result.alert_event === 'backlink_dead') return '连续网络失联（3/3）';
  if (result.backlink_status === 'unreachable') return `持续网络异常（${Number(result.failed_check_count || 0)}/3）`;
  if (result.backlink_status === 'dead') return '站点持续失联';
  return '反链正常';
}

function pingResultMessage(result = {}) {
  if (result.skipped) return '连通性免检，未执行探活';
  if (result.alert_event === 'ping_recovered') return '站点连通已恢复';
  if (result.alert_event === 'ping_first_failure') return '首次连通异常（1/3）';
  if (result.alert_event === 'ping_offline') return '连续三次探活失败';
  if (result.error) return `持续连通异常（${Number(result.ping_failed_count || 0)}/3）`;
  return '站点连通正常';
}

function pingAllLinks(req, res) {
  if (PingService.isPingInspectionInProgress() || hasRunningInspectionJob('ping')) {
    return fail(res, '链群健康体检正在执行，请稍后再试', 409);
  }
  const job = startInspectionJob('ping', '后台手动链群健康体检', onProgress => (
    PingService.runFullPingInspection({
      mode: 'manual',
      sendAdminAlert,
      aggregateAlerts: true,
      alwaysSendSummary: true,
      includeAllResultsInSummary: true,
      alertTaskLabel: '后台手动链群健康体检',
      onDataChanged: CacheService.clearPublicCache,
      onProgress
    })
  ));
  if (!job) return fail(res, '服务正在停止或任务队列已满，暂时无法启动体检', 503);
  return res.status(202).json({
    code: 200,
    msg: '已在后台启动链群健康体检',
    data: publicInspectionJob(job)
  });
}

function getInspectionJob(req, res) {
  cleanupInspectionJobs();
  const job = inspectionJobs.get(String(req.params.jobId || ''));
  if (!job) return fail(res, '任务不存在或服务已重启，无法继续读取任务状态', 404);
  return ok(res, publicInspectionJob(job));
}

async function resetLostCount(req, res) {
  try {
    const result = await PartnerModel.resetLostCount(Number(req.params.id));
    if (!result.changes) return fail(res, '友链不存在', 404);
    return ok(res, null, '掉链统计已重置');
  } catch {
    return fail(res, '重置掉链统计失败', 500);
  }
}

async function resetCheckStatus(req, res) {
  try {
    const id = Number.parseInt(String(req.params.id || ''), 10);
    if (!Number.isSafeInteger(id) || id <= 0) return fail(res, '友链编号不合法');
    const result = await PartnerModel.resetCheckStatus(id);
    if (!result.changes) return fail(res, '友链不存在', 404);
    CacheService.clearPublicCache();
    return ok(res, {
      id,
      backlink_status: 'pending',
      check_status_text: '待检测',
      failed_check_count: 0,
      check_fail_count: 0,
      ping_status: 'ok',
      ping_status_text: '待探活',
      ping_failed_count: 0,
      last_checked_at: null,
      last_ping_at: null
    }, '巡检状态已重置');
  } catch (error) {
    console.error('重置巡检状态失败：', error);
    return fail(res, safeApiErrorMessage(error, '重置巡检状态失败'), 500);
  }
}

async function getLogs(req, res) {
  try { return ok(res, await LogModel.searchInboundLogs(String(req.query.q || '').trim())); }
  catch { return fail(res, '获取入站日志失败', 500); }
}

async function getRejectedInboundLogs(req, res) {
  try { return ok(res, await LogModel.searchRejectedInboundLogs(String(req.query.q || '').trim())); }
  catch (error) {
    console.error('获取未入站用户明细失败：', error);
    return fail(res, '获取未入站用户明细失败', 500);
  }
}

async function getCategories(req, res) {
  try { return ok(res, await SystemModel.listAdminCategories()); }
  catch { return fail(res, '获取分类失败', 500); }
}

async function createCategory(req, res) {
  try {
    const name = String(req.body?.name || '').trim();
    if (!name) return fail(res, '分类名称不能为空');
    await SystemModel.createCategory(name);
    CacheService.clearPublicCache();
    return ok(res, null, '分类已新增');
  } catch (error) {
    return fail(res, String(error.message || '').includes('UNIQUE') ? '分类名称已存在' : '新增分类失败');
  }
}

async function saveCategoryOrder(req, res) {
  try {
    const items = req.body?.items;
    if (!Array.isArray(items)) return fail(res, '排序数据不合法');
    await SystemModel.saveCategoryOrder(items);
    CacheService.clearPublicCache();
    return ok(res, null, '分类排序已保存');
  } catch {
    return fail(res, '保存分类失败', 500);
  }
}

async function deleteCategory(req, res) {
  try {
    const result = await SystemModel.deleteCategory(req.params.id);
    if (result.used) return fail(res, '该分类下仍有友链，不能删除');
    CacheService.clearPublicCache();
    return ok(res, null, '分类已删除');
  } catch {
    return fail(res, '删除分类失败', 500);
  }
}

function parseAdPayload(body = {}) {
  const adType = String(body.ad_type || body.adType || 'normal').trim().toLowerCase();
  const adPosition = String(body.ad_position || body.adPosition || 'banner').trim().toLowerCase();
  const requestedPlatform = String(body.platform || 'all').trim().toLowerCase();
  const title = String(body.title || '').trim();
  if (!AdModel.ACTIVE_TYPES.has(adType)) throw new Error('请选择有效的广告类型');
  if (!AdModel.ACTIVE_POSITIONS.has(adPosition)) throw new Error('请选择有效的广告位置');
  if (!AdModel.ACTIVE_PLATFORMS.has(requestedPlatform)) throw new Error('请选择有效的显示端');
  if (adType === 'normal' && !AdModel.NORMAL_POSITIONS.has(adPosition)) {
    throw new Error('普通图链只能使用常规横幅或网格图标位置');
  }
  if (adType === 'code' && !AdModel.CODE_POSITIONS.has(adPosition)) {
    throw new Error('代码联盟只能使用顶部、底部或图标悬浮位置');
  }
  if (!title) throw new Error('广告标题不能为空');
  if (title.length > 80) throw new Error('广告标题不能超过 80 个字符');
  const description = String(body.description || '').trim();
  if (description.length > 300) throw new Error('广告介绍不能超过 300 个字符');
  // 联盟代码按管理员提交内容原样保存；兼容 document.write、iframe 与第三方混淆脚本。
  const submittedCode = String(body.ad_code || body.adCode || '');
  if (adType === 'code' && !submittedCode.trim()) throw new Error('代码联盟类型必须填写自定义代码');

  const parseOptionalUrl = (value, label, required = false) => {
    if (!String(value || '').trim()) {
      if (required) throw new Error(`${label}不能为空`);
      return '';
    }
    const normalized = normalizeUrl(value);
    let parsed;
    try { parsed = new URL(normalized); } catch { throw new Error(`${label}格式不正确`); }
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(`${label}仅支持 HTTP/HTTPS`);
    return parsed.href;
  };
  const adCode = adType === 'code' ? submittedCode : '';
  const imageUrl = adType === 'normal' ? parseOptionalUrl(body.image_url || body.imageUrl, '图片链接', true) : '';
  const targetUrl = adType === 'normal' ? parseOptionalUrl(body.target_url || body.targetUrl, '广告链接', true) : '';
  const sortOrder = Number(body.sort_order ?? 0);
  if (!Number.isInteger(sortOrder) || sortOrder < 0 || sortOrder > 999999) throw new Error('排序权重必须是 0 到 999999 的整数');
  const status = body.status === undefined ? 1 : Number(body.status);
  if (![0, 1].includes(status)) throw new Error('广告状态不合法');
  const platform = adType === 'code' ? 'all' : requestedPlatform;
  return { title, description, adType, adPosition, platform, adCode, imageUrl, targetUrl, sortOrder, status };
}

function parseCsvRows(source) {
  const text = String(source || '').replace(/^\uFEFF/, '');
  const records = [];
  let row = [], field = '', quoted = false;
  for (let index = 0; index <= text.length; index += 1) {
    const char = text[index] ?? '\n';
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') { field += '"'; index += 1; }
      else if (char === '"') quoted = false;
      else field += char;
      continue;
    }
    if (char === '"') { quoted = true; continue; }
    if (char === ',') { row.push(field.trim()); field = ''; continue; }
    if (char === '\r') continue;
    if (char === '\n') { row.push(field.trim()); field = ''; if (row.some(value => value !== '')) records.push(row); row = []; continue; }
    field += char;
  }
  if (quoted) throw new Error('CSV 引号未闭合');
  if (records[0]?.[0] && /^(广告类型|类型|ad_type|type)$/i.test(records[0][0])) records.shift();
  return records;
}

function csvType(value) {
  const type = String(value || '').trim().toLowerCase();
  if (['normal', '普通图链', '普通', 'banner', 'icon', '顶部横幅', '横幅', '网格图标', '图标'].includes(type)) return 'normal';
  if (['code', '代码联盟', '联盟代码', '自定义代码'].includes(type)) return 'code';
  return type;
}

function csvPosition(value, legacyType = '') {
  const position = String(value || '').trim().toLowerCase();
  const modes = {
    normal: 'banner', banner: 'banner', '常规': 'banner', '常规横幅': 'banner', '横幅': 'banner',
    icon: 'icon', '网格图标': 'icon', '图标': 'icon',
    top_float: 'top_float', '顶部悬浮': 'top_float',
    bottom_float: 'bottom_float', '底部悬浮': 'bottom_float',
    icon_float: 'icon_float', '小图标悬浮': 'icon_float'
  };
  return modes[position] || (String(legacyType).toLowerCase() === 'icon' ? 'icon' : position);
}

function csvPlatform(value) {
  const platform = String(value || 'all').trim().toLowerCase();
  const values = {
    all: 'all', '全部': 'all', '全部显示': 'all',
    pc: 'pc', '电脑': 'pc', '仅电脑端': 'pc',
    ios: 'ios', '仅ios': 'ios', '仅ios端': 'ios',
    non_ios: 'non_ios', '非ios': 'non_ios', '非ios端': 'non_ios',
    android: 'android', '安卓': 'android', '仅安卓端': 'android',
    harmony: 'harmony', '鸿蒙': 'harmony', '仅鸿蒙端': 'harmony'
  };
  return values[platform] || platform;
}

function csvStatus(value) {
  const normalized = String(value ?? '').trim().toLowerCase();
  return ['0', 'false', 'off', '停用', '禁用'].includes(normalized) ? 0 : 1;
}

async function getAds(req, res) {
  try { return ok(res, await AdModel.listAds()); }
  catch (error) { console.error('获取广告列表失败：', error); return fail(res, '获取广告列表失败', 500); }
}

async function createAd(req, res) {
  try {
    const result = await AdModel.createAd(parseAdPayload(req.body));
    CacheService.clearPublicCache();
    return ok(res, { id: result.id }, '广告已新增');
  } catch (error) {
    console.error('新增广告失败：', error);
    return fail(res, safeApiErrorMessage(error, '新增广告失败'), 400);
  }
}

async function updateAd(req, res) {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id <= 0) return fail(res, '广告编号不合法');
    const existing = await AdModel.getAdById(id);
    if (!existing) return fail(res, '广告不存在', 404);
    const result = await AdModel.updateAd(id, parseAdPayload({ ...existing, ...req.body }));
    CacheService.clearPublicCache();
    return ok(res, { changes: result.changes }, '广告已更新');
  } catch (error) {
    console.error('更新广告失败：', error);
    return fail(res, safeApiErrorMessage(error, '更新广告失败'), 400);
  }
}

async function updateAdStatus(req, res) {
  try {
    const id = Number(req.params.id), status = Number(req.body?.status);
    if (!Number.isSafeInteger(id) || id <= 0 || ![0, 1].includes(status)) return fail(res, '参数不合法');
    const result = await AdModel.setAdStatus(id, status);
    if (!result.changes) return fail(res, '广告不存在', 404);
    CacheService.clearPublicCache();
    return ok(res, null, status ? '广告已启用' : '广告已停用');
  } catch (error) {
    console.error('更新广告状态失败：', error);
    return fail(res, '更新广告状态失败', 500);
  }
}

async function deleteAd(req, res) {
  try {
    const result = await AdModel.deleteAd(Number(req.params.id));
    if (!result.changes) return fail(res, '广告不存在', 404);
    CacheService.clearPublicCache();
    return ok(res, null, '广告已删除');
  } catch (error) {
    console.error('删除广告失败：', error);
    return fail(res, '删除广告失败', 500);
  }
}

async function syncAdsCsv(req, res) {
  try {
    const rawRows = parseCsvRows(req.body?.csv);
    if (!rawRows.length) return fail(res, 'CSV 内容为空');
    const rows = rawRows.map((columns, index) => {
      // 新格式：类型, 位置, 显示端, 标题, 介绍, 自定义代码, 图片, 跳转, 排序, 状态。
      // 继续兼容旧 banner/icon CSV，升级时不会丢失存量配置。
      const isNewFormat = ['normal', 'code', '普通图链', '代码联盟', '联盟代码', '自定义代码'].includes(String(columns[0] || '').trim().toLowerCase());
      const hasPlatformColumn = isNewFormat && columns.length >= 10;
      const values = isNewFormat
        ? (hasPlatformColumn
          ? { ad_type: csvType(columns[0]), ad_position: csvPosition(columns[1]), platform: csvPlatform(columns[2]), title: columns[3], description: columns[4], ad_code: columns[5], image_url: columns[6], target_url: columns[7], sort_order: columns[8], status: columns[9] }
          : { ad_type: csvType(columns[0]), ad_position: csvPosition(columns[1]), platform: 'all', title: columns[2], description: columns[3], ad_code: columns[4], image_url: columns[5], target_url: columns[6], sort_order: columns[7], status: columns[8] })
        : { ad_type: 'normal', ad_position: csvPosition('', columns[0]), platform: 'all', title: columns[1], description: columns[2] || '', ad_code: '', image_url: columns[3] || columns[2], target_url: columns[4] || columns[3], sort_order: columns[5] || columns[4], status: columns[6] || columns[5] };
      try {
        return parseAdPayload({ ...values, status: csvStatus(values.status) });
      } catch (error) {
        throw new Error(`第 ${index + 1} 行：${error.message}`);
      }
    });
    const result = await AdModel.syncAdsFromCsv(rows);
    CacheService.clearPublicCache();
    return ok(res, result, `同步完成：新增 ${result.inserted} 条，更新 ${result.updated} 条`);
  } catch (error) {
    console.error('CSV 同步广告失败：', error);
    return fail(res, safeApiErrorMessage(error, 'CSV 同步失败'), 400);
  }
}

function clearMirrorDependencies() {
  CacheService.clearPublicCache();
  require('./PublicController').clearMirrorsCache();
}

async function syncMirrorPartnersAndCache() {
  const result = await MirrorModel.syncMirrorsToPartners();
  await SourceTokenModel.ensureAllPartnersHaveSid();
  clearMirrorDependencies();
  return result;
}

function parseMirrorPayload(body = {}) {
  return MirrorModel.normalizeMirrorPayload({
    speed_name: body.speed_name,
    partner_name: body.partner_name,
    url: body.url,
    status: body.status
  });
}

function csvMirrorStatus(value) {
  return ['0', 'false', 'off', '停用', '禁用'].includes(String(value ?? '').trim().toLowerCase()) ? 0 : 1;
}

async function getMirrors(req, res) {
  try { return ok(res, await MirrorModel.getAllMirrors()); }
  catch (error) { console.error('获取节点列表失败：', error); return fail(res, '获取节点列表失败', 500); }
}

async function createMirror(req, res) {
  try {
    const mirror = parseMirrorPayload(req.body);
    await MirrorModel.createMirror(mirror);
    await syncMirrorPartnersAndCache();
    return ok(res, { url: mirror.url }, '节点已新增');
  } catch (error) {
    console.error('新增节点失败：', error);
    return fail(res, safeApiErrorMessage(error, '新增节点失败'), 400);
  }
}

async function updateMirror(req, res) {
  try {
    const originalUrl = String(req.params.url || '');
    const existing = await MirrorModel.getMirrorByUrl(originalUrl);
    if (!existing) return fail(res, '节点不存在', 404);
    const mirror = parseMirrorPayload({ ...existing, ...req.body });
    const result = await MirrorModel.updateMirror(originalUrl, mirror);
    if (!result.changes) return fail(res, '节点不存在', 404);
    await syncMirrorPartnersAndCache();
    return ok(res, { url: mirror.url }, '节点已更新');
  } catch (error) {
    console.error('更新节点失败：', error);
    return fail(res, safeApiErrorMessage(error, '更新节点失败'), 400);
  }
}

async function updateMirrorStatus(req, res) {
  try {
    const result = await MirrorModel.setMirrorStatus(req.params.url, req.body?.status);
    if (!result.changes) return fail(res, '节点不存在', 404);
    await syncMirrorPartnersAndCache();
    return ok(res, null, Number(req.body.status) ? '节点已启用' : '节点已停用');
  } catch (error) {
    return fail(res, safeApiErrorMessage(error, '更新节点状态失败'), 400);
  }
}

async function deleteMirror(req, res) {
  try {
    const result = await MirrorModel.deleteMirror(req.params.url);
    if (!result.changes) return fail(res, '节点不存在', 404);
    await syncMirrorPartnersAndCache();
    return ok(res, null, '节点已删除');
  } catch (error) {
    return fail(res, safeApiErrorMessage(error, '删除节点失败'), 400);
  }
}

async function syncMirrorsCsv(req, res) {
  try {
    const rawRows = parseCsvRows(req.body?.csv);
    if (rawRows[0]?.[0] && /^(测速名|speed[_ ]?name)$/i.test(rawRows[0][0])) rawRows.shift();
    if (!rawRows.length) return fail(res, 'CSV 内容为空');
    const rows = rawRows.map((columns, index) => {
      try {
        return parseMirrorPayload({
          speed_name: columns[0],
          partner_name: columns[1],
          url: columns[2],
          status: csvMirrorStatus(columns[3])
        });
      } catch (error) {
        throw new Error(`第 ${index + 1} 行：${error.message}`);
      }
    });
    const result = await MirrorModel.syncMirrorsFromCsv(rows);
    await syncMirrorPartnersAndCache();
    return ok(res, result, `同步完成：新增 ${result.inserted} 条，更新 ${result.updated} 条，移除 ${result.deleted} 条`);
  } catch (error) {
    console.error('CSV 同步节点失败：', error);
    return fail(res, safeApiErrorMessage(error, 'CSV 同步失败'), 400);
  }
}

const MATRIX_HEADERS = {
  partners: ['网站名称', '网站地址(URL)', '所属分类', '站长联系方式', '反链检测网址', '简易描述', '排序权重', '状态(1/0)', '是否同步(1/0)'],
  ads: ['广告类型', '广告位置', '广告标题', '广告介绍', '自定义代码', '图片链接', '跳转链接', '排序权重', '状态(1/0)', '是否同步(1/0)'],
  mirrors: ['测速名', '友链霸榜名', 'URL', '状态(1/0)', '是否同步(1/0)']
};

function parseMatrixCsv(source, type) {
  const requiredHeaders = MATRIX_HEADERS[type];
  const records = parseCsv(String(source || ''), {
    bom: true,
    skip_empty_lines: true,
    relax_column_count: true
  });
  if (!records.length) throw new Error('CSV 内容为空');
  const headers = records.shift().map(value => String(value || '').trim());
  const missing = requiredHeaders.filter(header => !headers.includes(header));
  if (missing.length) throw new Error(`CSV 缺少表头：${missing.join('、')}`);

  return records.map((columns, rowIndex) => {
    const row = {};
    headers.forEach((header, index) => { row[header] = String(columns[index] ?? '').trim(); });
    row.__line = rowIndex + 2;
    return row;
  }).filter(row => row['是否同步(1/0)'] === '1');
}

function strictBinaryFlag(value, label, line) {
  const normalized = String(value ?? '').trim();
  if (!['0', '1'].includes(normalized)) throw new Error(`第 ${line} 行：${label} 必须是 1 或 0`);
  return Number(normalized);
}

function normalizeMatrixUrl(value, label, line, required = true) {
  const raw = String(value || '').trim();
  if (!raw && !required) return '';
  if (!raw) throw new Error(`第 ${line} 行：${label}不能为空`);
  let normalized;
  try { normalized = normalizeUrl(raw); } catch { throw new Error(`第 ${line} 行：${label}格式不正确`); }
  const hostname = parseHostname(normalized);
  if (!hostname) throw new Error(`第 ${line} 行：${label}格式不正确`);
  return normalized.replace(/\/$/, '');
}

function normalizeMatrixInteger(value, label, line) {
  const normalized = String(value ?? '').trim() || '0';
  const number = Number(normalized);
  if (!Number.isSafeInteger(number) || number < 0 || number > 999999) {
    throw new Error(`第 ${line} 行：${label}必须是 0 到 999999 的整数`);
  }
  return number;
}

async function fetchMatrixCsv(configKey, type) {
  const sourceUrl = String(await SystemModel.configValue(configKey) || '').trim();
  if (!sourceUrl) throw new Error('请先在系统设置中保存对应的 CSV 直链');
  const response = await InspectionService.fetchWithRetry(sourceUrl);
  if (response.status < 200 || response.status >= 400) throw new Error(`CSV 拉取失败：HTTP ${response.status}`);
  return parseMatrixCsv(response.data, type);
}

function ensureUnique(items, selector, label) {
  const seen = new Set();
  for (const item of items) {
    const key = selector(item);
    if (seen.has(key)) throw new Error(`CSV 存在重复${label}：${key}`);
    seen.add(key);
  }
}

async function syncPartnersMatrix(req, res) {
  try {
    const sourceRows = await fetchMatrixCsv('csv_url_partners', 'partners');
    const rowsByDomain = new Map();
    const duplicateDomains = new Set();
    for (const row of sourceRows) {
      const normalized = normalizePartnerUrl(row['网站地址(URL)']);
      const name = row['网站名称'];
      const category = row['所属分类'];
      if (!name) throw new Error(`第 ${row.__line} 行：网站名称不能为空`);
      if (!category) throw new Error(`第 ${row.__line} 行：所属分类不能为空`);
      if (rowsByDomain.has(normalized.domain)) duplicateDomains.add(normalized.domain);
      rowsByDomain.set(normalized.domain, {
        name,
        url: normalized.url,
        domain: normalized.domain,
        category,
        contact: row['站长联系方式'],
        backlinkUrl: normalizeMatrixUrl(row['反链检测网址'], '反链检测网址', row.__line, false) || null,
        description: row['简易描述'],
        priority: normalizeMatrixInteger(row['排序权重'], '排序权重', row.__line),
        status: strictBinaryFlag(row['状态(1/0)'], '状态', row.__line)
      });
    }
    const items = [...rowsByDomain.values()];
    const result = await PartnerModel.syncPartnersFromCsv(items);
    CacheService.clearPublicCache();
    return ok(res, { type: 'partners', ...result, duplicateDomains: [...duplicateDomains] }, `友链新增 ${result.inserted} 条，更新 ${result.updated} 条${duplicateDomains.size ? `；合并重复域名 ${duplicateDomains.size} 条` : ''}`);
  } catch (error) {
    console.error('CSV 矩阵同步友链失败：', error);
    return fail(res, safeApiErrorMessage(error, '友链同步失败'), 400);
  }
}

async function syncAdsMatrix(req, res) {
  try {
    const sourceRows = await fetchMatrixCsv('csv_url_ads', 'ads');
    const items = sourceRows.map(row => parseAdPayload({
      ad_type: csvType(row['广告类型']),
      ad_position: csvPosition(row['广告位置']),
      platform: 'all',
      title: row['广告标题'],
      description: row['广告介绍'],
      ad_code: row['自定义代码'],
      image_url: row['图片链接'],
      target_url: row['跳转链接'],
      sort_order: normalizeMatrixInteger(row['排序权重'], '排序权重', row.__line),
      status: strictBinaryFlag(row['状态(1/0)'], '状态', row.__line)
    }));
    const result = await AdModel.replaceAdsFromCsv(items);
    CacheService.clearPublicCache();
    return ok(res, { type: 'ads', ...result }, `广告全覆盖 ${result.total} 条`);
  } catch (error) {
    console.error('CSV 矩阵同步广告失败：', error);
    return fail(res, safeApiErrorMessage(error, '广告同步失败'), 400);
  }
}

async function syncMirrorsMatrix(req, res) {
  try {
    const [sourceRows, siteUrl] = await Promise.all([
      fetchMatrixCsv('csv_url_mirrors', 'mirrors'),
      SystemModel.configValue('site_url')
    ]);
    const siteHostname = parseHostname(siteUrl);
    let excluded = 0;
    const items = sourceRows.map(row => ({
      speed_name: row['测速名'],
      partner_name: row['友链霸榜名'],
      url: normalizeMatrixUrl(row.URL, 'URL', row.__line),
      status: strictBinaryFlag(row['状态(1/0)'], '状态', row.__line)
    })).filter(item => {
      const hostname = parseHostname(item.url);
      const isCurrentSite = siteHostname && (
        matchesPartnerDomain(hostname, siteHostname) || matchesPartnerDomain(siteHostname, hostname)
      );
      if (isCurrentSite) excluded += 1;
      return !isCurrentSite;
    });
    ensureUnique(items, item => item.url, '节点地址');
    const result = await MirrorModel.replaceMirrorsFromCsv(items);
    const partners = await syncMirrorPartnersAndCache();
    return ok(res, { type: 'mirrors', ...result, excluded, partners }, `节点全覆盖 ${result.total} 条`);
  } catch (error) {
    console.error('CSV 矩阵同步节点失败：', error);
    return fail(res, safeApiErrorMessage(error, '节点同步失败'), 400);
  }
}

function csvEscape(value) {
  const text = String(value ?? '');
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function createCsv(headers, rows) {
  return `\uFEFF${[headers, ...rows].map(row => row.map(csvEscape).join(',')).join('\r\n')}\r\n`;
}

async function buildMatrixExports() {
  const [partners, ads, mirrors, siteName] = await Promise.all([
    PartnerModel.listPartnersForExport(),
    AdModel.listAdsForExport(),
    MirrorModel.getAllMirrors(),
    SystemModel.configValue('site_name')
  ]);
  const files = {
    partners: createCsv(MATRIX_HEADERS.partners, partners.map(item => [
      item.name, item.url, item.category, item.contact, item.backlink_url,
      item.description, item.priority, item.is_approved, 1
    ])),
    ads: createCsv(MATRIX_HEADERS.ads, ads.map(item => [
      item.ad_type, item.ad_position, item.title, item.description, item.ad_code,
      item.image_url, item.target_url, item.sort_order, item.status, 1
    ])),
    mirrors: createCsv(MATRIX_HEADERS.mirrors, mirrors.map(item => [
      item.speed_name, item.partner_name, item.url, item.status, 1
    ]))
  };
  return { files, siteName: String(siteName || '网站').replace(/[\\/:*?"<>|]/g, '_') };
}

function setDownloadName(res, asciiName, displayName) {
  res.setHeader('Content-Disposition', `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(displayName)}`);
}

async function exportMatrix(req, res) {
  try {
    const type = String(req.params.type || '').toLowerCase();
    if (!['partners', 'ads', 'mirrors', 'all'].includes(type)) return fail(res, '不支持的导出类型', 404);
    const { files, siteName } = await buildMatrixExports();
    const labels = { partners: '友链表', ads: '广告表', mirrors: '节点表' };
    if (type !== 'all') {
      res.type('text/csv; charset=utf-8');
      setDownloadName(res, `${type}.csv`, `${siteName}_${labels[type]}.csv`);
      return res.send(files[type]);
    }

    res.type('application/zip');
    setDownloadName(res, 'matrix-backup.zip', `${siteName}_全站矩阵备份.zip`);
    const archive = new ZipArchive({ zlib: { level: 6 } });
    archive.on('error', error => {
      console.error('生成矩阵备份压缩包失败：', error);
      if (!res.headersSent) fail(res, '生成备份失败', 500);
      else res.destroy(error);
    });
    archive.pipe(res);
    for (const key of ['partners', 'ads', 'mirrors']) {
      archive.append(files[key], { name: `${siteName}_${labels[key]}.csv` });
    }
    await archive.finalize();
  } catch (error) {
    console.error('导出矩阵数据失败：', error);
    if (!res.headersSent) return fail(res, safeApiErrorMessage(error, '导出失败'), 500);
  }
}

function renderAdminHtml(res, fileName) {
  const file = path.join(__dirname, '..', '..', 'public', 'admin', fileName);
  const nonce = crypto.randomBytes(16).toString('base64');
  const policy = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "script-src-attr 'none'",
    `style-src 'self' 'nonce-${nonce}'`,
    "style-src-attr 'none'",
    "img-src 'self' data: https: http:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-src 'none'",
    "worker-src 'none'"
  ].join('; ');

  // index.html 已固定引用 monitor.js；这里只为内联基础样式与启动脚本注入一次性 nonce。
  const html = fs.readFileSync(file, 'utf8')
    .replace('<style>', `<style nonce="${nonce}">`)
    .replace('<script>', `<script nonce="${nonce}">`);

  res.setHeader('Content-Security-Policy', policy);
  res.setHeader('Cache-Control', 'no-store');
  return res.type('html').send(html);
}

function renderAdminPage(req, res) {
  return renderAdminHtml(res, 'index.html');
}

module.exports = {
  login,
  changePassword,
  getAnalyticsConfig,
  saveAnalyticsConfig,
  getSettings,
  getRiskControlSettings,
  saveSettings,
  uploadSiteLogo,
  testWebhook,
  testBark,
  getWebhookHealth,
  listWebhookDeliveries,
  getReview,
  getOverview,
  getDashboardStats,
  getSiteTrafficTrend,
  getPartners,
  getPartnerAnalytics,
  createPartner,
  updatePartner,
  updatePartnerApproval,
  whitelistPartner,
  clearPartnerTraffic,
  deletePartner,
  regeneratePartnerSourceSid,
  checkAllLinks,
  pingAllLinks,
  getInspectionJob,
  checkLink,
  inspectLink,
  checkLinkHealth,
  resetLostCount,
  resetCheckStatus,
  getLogs,
  getRejectedInboundLogs,
  getCategories,
  createCategory,
  saveCategoryOrder,
  deleteCategory,
  getAds,
  createAd,
  updateAd,
  updateAdStatus,
  deleteAd,
  syncAdsCsv,
  getMirrors,
  createMirror,
  updateMirror,
  updateMirrorStatus,
  deleteMirror,
  syncMirrorsCsv,
  syncPartnersMatrix,
  syncAdsMatrix,
  syncMirrorsMatrix,
  exportMatrix,
  renderAdminPage
};
