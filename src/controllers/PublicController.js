'use strict';

const crypto = require('crypto');
const path = require('path');
const { dbWriteCoordinator } = require('../services/DbWriteCoordinator');
const jwt = require('jsonwebtoken');
const svgCaptcha = require('svg-captcha');
const { Mutex } = require('async-mutex');
const {
  IS_PRODUCTION,
  GUEST_JWT_SECRET,
  TRAFFIC_DEBUG
} = require('../config/env');
const { getClientIp, parseHostname, matchesPartnerDomain, normalizePartnerUrl, normalizeRegisteredDomain } = require('../utils/network');
const { ok, fail, safeApiErrorMessage, isUniqueConstraintError } = require('../utils/http');
const { buildSourceEntryUrls } = require('../utils/sourceLinks');
const {
  VERIFY_NONCE_TTL_MS,
  VERIFY_COOKIE_TTL_MS,
  GUEST_VERIFY_COOKIE,
  storePendingTrafficReferer,
  readPendingTrafficReferer,
  clearPendingTrafficReferer,
  storePendingTrafficSource,
  readPendingTrafficSource,
  clearPendingTrafficSource,
  getCookie,
  ensureVisitorIdentity,
  isPartnerVisitRateLimited,
  storeVerificationNonce,
  getVerificationNonce,
  consumeVerificationNonce
} = require('../middlewares/rateLimit');
const PartnerModel = require('../models/PartnerModel');
const SourceTokenModel = require('../models/SourceTokenModel');
const LogModel = require('../models/LogModel');
const SystemModel = require('../models/SystemModel');
const AdModel = require('../models/AdsModel');
const MirrorModel = require('../models/MirrorModel');
const CacheService = require('../services/CacheService');
const { sendAdminAlert, formatAlertLink, formatContactLine } = require('../services/AlertService');

const CLAIM_TTL_SECONDS = 15 * 60;
const ATTRIBUTION_COOKIE = 'inflow_visit';
const ATTRIBUTION_TTL_SECONDS = 30 * 60;
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
const dbMutex = new Mutex();
const MIRRORS_CACHE_TTL_MS = 60 * 1000;
const SHOWCASE_DIAGNOSTIC_PHASES = new Set(['top_float', 'bottom_float', 'icon_float']);
let mirrorsCache = { data: null, expireTime: 0 };

function clearMirrorsCache() {
  mirrorsCache = { data: null, expireTime: 0 };
}

function trafficDebug(message) {
  if (TRAFFIC_DEBUG) console.log(`[流量排查] ${message}`);
}

function readAttributionVisit(req) {
  const token = decodeURIComponent(getCookie(req, ATTRIBUTION_COOKIE) || '');
  if (!token) return null;
  try {
    const payload = jwt.verify(token, GUEST_JWT_SECRET);
    if (payload?.type !== 'inflow-attribution'
      || typeof payload.visitId !== 'string'
      || !Number.isSafeInteger(Number(payload.sourcePartnerId))) return null;
    return { visitId: payload.visitId, sourcePartnerId: Number(payload.sourcePartnerId) };
  } catch {
    return null;
  }
}

async function isLegitUser(req, refererOverride = '', { trustedSource = false } = {}) {
  const ua = String(req.headers['user-agent'] || '').trim();
  const invalidUa = /curl|python|requests|headlesschrome|postman|wget|httpclient|scrapy|bot|spider|crawl|slurp/i;
  if (!ua || invalidUa.test(ua)) {
    req.trafficBlockReason = '爬虫、无头浏览器或异常 User-Agent';
    return false;
  }

  // 有效 SID 已在前置中间件中完成数据库解析和签名绑定；Referer 仅用于观察，
  // 不能因为浏览器隐私策略将其删除而否定 SID 归属。
  if (trustedSource) return true;

  const referer = String(refererOverride || req.get('Referer') || '').trim();
  let refererUrl;
  try { refererUrl = new URL(referer); } catch {
    req.trafficBlockReason = '缺失或伪造 Referer';
    return false;
  }
  if (!/^https?:$/.test(refererUrl.protocol)) {
    req.trafficBlockReason = 'Referer 协议不合法';
    return false;
  }

  const sourceHost = parseHostname(referer);
  const ownUrlText = await SystemModel.configValue('site_url');
  const ownHost = parseHostname(ownUrlText);
  let ownUrl = null;
  try { ownUrl = new URL(ownUrlText); } catch { /* 未配置本站地址时跳过本站来源判断。 */ }
  const localHosts = new Set(['localhost', '127.0.0.1', '::1']);
  const isDifferentLocalPort = ownUrl
    && localHosts.has(sourceHost)
    && sourceHost === parseHostname(ownUrl.href)
    && refererUrl.port !== ownUrl.port;
  if (!sourceHost || (ownHost && matchesPartnerDomain(sourceHost, ownHost) && !isDifferentLocalPort)) {
    req.trafficBlockReason = '本站来源或无效 Referer';
    return false;
  }
  return true;
}

function extractSourceSid(req) {
  const pathMatch = String(req.path || '').match(/^\/r\/([^/]+)\/?$/);
  if (pathMatch) {
    try { return { present: true, value: decodeURIComponent(pathMatch[1]) }; }
    catch { return { present: true, value: '' }; }
  }
  if (req.path === '/' && req.query && Object.prototype.hasOwnProperty.call(req.query, 'sid')) {
    return { present: true, value: String(req.query.sid || '').trim() };
  }
  return { present: false, value: '' };
}

function cleanSidLandingUrl(req) {
  if (String(req.path || '').startsWith('/r/')) return '/';
  const query = String(req.originalUrl || '').split('?')[1] || '';
  const params = new URLSearchParams(query);
  params.delete('sid');
  const suffix = params.toString();
  return `${req.path || '/'}${suffix ? `?${suffix}` : ''}`;
}

async function resolveSidLanding(req) {
  const sidInput = extractSourceSid(req);
  if (!sidInput.present) return null;

  const referer = String(req.get('Referer') || req.get('Referrer') || '').trim();
  const observedDomain = normalizeRegisteredDomain(parseHostname(referer));
  const [sidBinding, candidates] = await Promise.all([
    SourceTokenModel.findActiveSid(sidInput.value),
    PartnerModel.listInflowCandidates()
  ]);
  const domainPartner = observedDomain
    ? candidates.find(item => normalizeRegisteredDomain(item.domain) === observedDomain)
    : null;

  let partnerId = null;
  let method = 'unattributed';
  if (domainPartner) {
    partnerId = domainPartner.id;
    if (!sidInput.value) method = 'domain_only';
    else if (!sidBinding) method = 'invalid_sid_domain_match';
    else if (Number(sidBinding.partner_id) === Number(domainPartner.id)) method = 'sid_domain_match';
    else method = 'sid_domain_mismatch';
  } else if (sidBinding) {
    partnerId = sidBinding.partner_id;
    method = observedDomain ? 'sid_fallback_unknown_domain' : 'sid_fallback_no_referer';
  } else {
    method = observedDomain ? 'invalid_sid_unknown_domain' : 'invalid_sid_no_referer';
  }

  return {
    partnerId,
    sourceTokenId: sidBinding?.token_id || null,
    sidPartnerId: sidBinding?.partner_id || null,
    domainPartnerId: domainPartner?.id || null,
    method,
    observedDomain,
    referer
  };
}

/**
 * 滑块门禁之前仅保存短效来源凭证。
 * 严禁在这里查询 24h 去重或写入 inbound_logs；正式计分只由 trackPing 完成。
 */
async function preVerifyInflowTraffic(req, res, next) {
  try {
    if (req.method !== 'GET') return next();
    const sidInput = extractSourceSid(req);
    if (sidInput.present) {
      const source = await resolveSidLanding(req);
      // 每次 SID 落地都覆盖旧归属；无效 SID 也必须清掉历史 Cookie，避免陈旧来源串号。
      clearPendingTrafficReferer(res);
      if (source?.partnerId) storePendingTrafficSource(req, res, source);
      else clearPendingTrafficSource(res);
      res.set('Cache-Control', 'private, no-store');
      res.set('Referrer-Policy', 'no-referrer');
      return res.redirect(302, cleanSidLandingUrl(req));
    }
    if (req.path !== '/') return next();
    const rawReferer = String(req.get('Referer') || req.get('Referrer') || '').trim();
    const ownHost = String(req.get('host') || '').toLowerCase();
    const refererHost = parseHostname(rawReferer);
    if (refererHost && !rawReferer.toLowerCase().includes(`://${ownHost}`)
      && !readPendingTrafficReferer(req)) {
      storePendingTrafficReferer(req, res, rawReferer);
    }
  } catch (error) {
    console.error('[流量排查] 暂存入站来源失败：', error.message);
  }
  return next();
}

/** 首页静态文件中间件：签发延迟心跳使用的短期认领凭证。 */
async function trackInflow(req, res, next) {
  try {
    if (req.method !== 'GET' || req.path !== '/') return next();
    const ip = getClientIp(req);
    const pendingSource = readPendingTrafficSource(req);
    const requestReferer = String(req.get('Referer') || '').trim();
    const restoredReferer = readPendingTrafficReferer(req);
    const effectiveReferer = pendingSource?.referer || restoredReferer || requestReferer;
    if (pendingSource) clearPendingTrafficSource(res);
    if (restoredReferer) clearPendingTrafficReferer(res);

    if (!ip || !(await isLegitUser(req, effectiveReferer, { trustedSource: Boolean(pendingSource) }))) {
      trafficDebug(`拦截原因: ${req.trafficBlockReason || '无法识别客户端 IP'}`);
      return next();
    }

    const candidates = await PartnerModel.listInflowCandidates();
    let partner = pendingSource
      ? candidates.find(item => Number(item.id) === Number(pendingSource.partnerId))
      : null;
    let observedDomain = pendingSource?.observedDomain || '';
    if (!partner) {
      const refererUrl = new URL(effectiveReferer);
      observedDomain = normalizeRegisteredDomain(refererUrl.hostname);
      partner = candidates.find(item => observedDomain === normalizeRegisteredDomain(item.domain));
    }
    if (!partner) return next();
    const now = Date.now();
    if (isPartnerVisitRateLimited(partner.id, ip)) {
      return next();
    }

    const token = crypto.randomBytes(24).toString('base64url');
    await LogModel.createClaimToken({
      tokenHash: crypto.createHash('sha256').update(token).digest('hex'),
      partnerId: partner.id,
      ip,
      ttlSeconds: CLAIM_TTL_SECONDS,
      startedAtMs: now,
      referer: effectiveReferer,
      sourceTokenId: pendingSource?.sourceTokenId || null,
      sidPartnerId: pendingSource?.sidPartnerId || null,
      domainPartnerId: pendingSource?.domainPartnerId || (pendingSource ? null : partner.id),
      attributionMethod: pendingSource?.method || 'domain_only',
      observedDomain
    });
    const cookieOptions = {
      maxAge: CLAIM_TTL_SECONDS * 1000,
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PRODUCTION,
      path: '/'
    };
    res.cookie('track_session', token, cookieOptions);
    res.cookie('inflow_claim', token, cookieOptions);
    return next();
  } catch (error) {
    console.error('[流量排查] 入站凭证签发失败：', error.message);
    return next();
  }
}

function health(req, res) {
  return res.status(200).json({
    status: 'ok',
    timestamp: Date.now(),
    dbWriteQueue: dbWriteCoordinator.getStats()
  });
}

function headRoot(req, res) {
  return res.status(200).end();
}

function favicon(req, res) {
  // Image 测速依赖可解码的图片；空 204 会触发 Image.onerror，导致正常节点被误判离线。
  res.set('Cache-Control', 'public, max-age=86400');
  return res.sendFile(path.join(__dirname, '..', '..', 'public', 'icons', 'icon-192.png'));
}

function initVerification(req, res) {
  const visitorId = ensureVisitorIdentity(req, res);
  const nonce = crypto.randomBytes(16).toString('hex');
  const issuedAt = Date.now();
  const rawData = `${nonce}-${issuedAt}`;
  const sign = crypto.createHmac('sha256', GUEST_JWT_SECRET).update(rawData).digest('hex');
  storeVerificationNonce(nonce, {
    issuedAt,
    expiresAt: issuedAt + VERIFY_NONCE_TTL_MS,
    ip: getClientIp(req),
    ua: String(req.get('user-agent') || '').slice(0, 300),
    visitorId
  });
  const token = `${rawData}.${sign}`;
  return res.json({ code: 200, msg: '验证令牌已生成', data: { token, expiresIn: 60 }, success: true, token });
}

function checkVerification(req, res) {
  const visitorId = ensureVisitorIdentity(req, res);
  const { token, tracks, duration, fingerprint = {}, isWebdriver } = req.body || {};
  const reject = (msg, status = 400) => res.status(status).json({ code: status, msg, data: null, success: false });
  if (!token || !Array.isArray(tracks) || isWebdriver || fingerprint.webdriver === true) return reject('环境异常或存在自动化脚本');
  if (tracks.length < 6 || tracks.length > 240) return reject('轨迹采样点数量异常');
  const dot = String(token).lastIndexOf('.');
  if (dot < 1) return reject('验证令牌格式错误');
  const rawData = String(token).slice(0, dot);
  const sign = String(token).slice(dot + 1);
  const expected = crypto.createHmac('sha256', GUEST_JWT_SECRET).update(rawData).digest('hex');
  if (sign.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sign), Buffer.from(expected))) {
    return reject('验证签名校验失败', 403);
  }
  const [nonce, timestampText] = rawData.split('-');
  const issuedAt = Number(timestampText);
  const record = getVerificationNonce(nonce);
  const verifiedAt = Date.now();
  if (!nonce || !Number.isFinite(issuedAt) || verifiedAt - issuedAt > VERIFY_NONCE_TTL_MS
    || verifiedAt < issuedAt || !record || record.expiresAt <= verifiedAt
    || Number(record.issuedAt) !== issuedAt) {
    return reject('验证已超时，请刷新重试');
  }
  if (record.ip !== getClientIp(req)
    || record.ua !== String(req.get('user-agent') || '').slice(0, 300)
    || record.visitorId !== visitorId) {
    return reject('验证环境已变化，请重新验证', 403);
  }
  consumeVerificationNonce(nonce);

  const elapsed = Number(duration);
  if (!Number.isFinite(elapsed) || elapsed < 250 || elapsed > 10000) return reject('滑动速度异常');
  const actualElapsed = verifiedAt - Number(record.issuedAt);
  if (actualElapsed < 300) return reject('滑动速度异常，请重新验证');
  if (Math.abs(actualElapsed - elapsed) > 1500) return reject('客户端计时与服务器计时不一致，请重新验证');
  const points = tracks.map(point => ({ x: Number(point?.x), y: Number(point?.y), t: Number(point?.t) }));
  if (points.some(point => !Number.isFinite(point.x) || !Number.isFinite(point.y)
    || !Number.isFinite(point.t) || point.t < 0 || point.t > elapsed)) return reject('轨迹数据格式异常');
  for (let index = 1; index < points.length; index += 1) {
    if (points[index].t < points[index - 1].t || points[index].x + 8 < points[index - 1].x) return reject('轨迹顺序异常');
  }
  const xTravel = Math.max(...points.map(point => point.x)) - Math.min(...points.map(point => point.x));
  const yRange = Math.max(...points.map(point => point.y)) - Math.min(...points.map(point => point.y));
  const xSteps = new Set(points.slice(1).map((point, index) => Math.max(0, Math.round(point.x - points[index].x)))).size;
  const timeSteps = new Set(points.slice(1).map((point, index) => Math.max(0, Math.round(point.t - points[index].t)))).size;
  if (xTravel < 80 || points[points.length - 1].t < 200 || (yRange < 1 && xSteps < 3 && timeSteps < 3)) {
    return reject('行为轨迹不符合人类操作特征');
  }

  const guestToken = jwt.sign(
    {
      scope: 'guest-verified',
      role: 'guest',
      type: 'guest-verification',
      visitorId,
      verifiedAt,
      riskVersion: 1
    },
    GUEST_JWT_SECRET,
    { expiresIn: '12h', algorithm: 'HS256' }
  );
  res.cookie(GUEST_VERIFY_COOKIE, guestToken, {
    maxAge: VERIFY_COOKIE_TTL_MS,
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PRODUCTION,
    path: '/'
  });
  return res.json({ code: 200, msg: '验证通过', data: { expiresIn: 12 * 60 * 60 }, success: true });
}

async function getAnalyticsConfig(req, res) {
  try {
    return ok(res, await SystemModel.getConfigValues(ANALYTICS_CONFIG_KEYS));
  } catch {
    return fail(res, '获取统计配置失败', 500);
  }
}

async function getInflowToken(req, res) {
  try {
    const token = decodeURIComponent(getCookie(req, 'inflow_claim'));
    if (!token) return ok(res, { token: null }, '当前访问没有可认领的入站来源');
    const row = await LogModel.getValidClaimTokenHash(crypto.createHash('sha256').update(token).digest('hex'));
    return ok(res, { token: row ? token : null });
  } catch {
    return fail(res, '获取入站凭证失败', 500);
  }
}

async function trackPing(req, res) {
  try {
    const body = req.body || {};
    const cookieToken = decodeURIComponent(getCookie(req, 'track_session') || getCookie(req, 'inflow_claim'));
    const suppliedToken = String(body.token || '');
    if (!cookieToken || (suppliedToken && suppliedToken !== cookieToken)) return fail(res, '追踪会话无效或已过期', 401);
    const tokenHash = crypto.createHash('sha256').update(cookieToken).digest('hex');
    const claim = await LogModel.getActiveClaim(tokenHash);
    if (!claim) return fail(res, '追踪会话已使用或已过期', 409);
    if (!claim.started_at_ms || Date.now() - Number(claim.started_at_ms) < 3000) return fail(res, '停留时间不足，暂不计入带量', 429);
    const clientIp = getClientIp(req);
    const ua = String(req.get('user-agent') || '').trim();
    if (clientIp !== claim.ip || !ua || /curl|python|requests|headlesschrome|postman|wget|httpclient|scrapy|bot|spider|crawl|slurp/i.test(ua)) {
      return fail(res, '访问环境校验未通过', 403);
    }

    const fingerprint = body.fingerprint && typeof body.fingerprint === 'object' ? body.fingerprint : {};
    const compliant = fingerprint.webdriver !== true && fingerprint.abnormalScreen !== true && fingerprint.missingLanguage !== true;
    if (!compliant) return fail(res, '访问环境校验未通过', 403);
    const visitId = crypto.randomUUID();
    const transactionResult = await dbMutex.runExclusive(() => LogModel.processTrackPing({
      tokenHash,
      claim,
      clientIp,
      userAgent: ua,
      visitId
    }));
    if (transactionResult.alreadyUsed) return fail(res, '追踪会话已使用', 409);
    const { newlyCounted, autoApproved } = transactionResult;
    if (newlyCounted || autoApproved) CacheService.clearPublicCache();
    const expiredCookie = { maxAge: 0, httpOnly: true, sameSite: 'lax', secure: IS_PRODUCTION, path: '/' };
    res.cookie('track_session', '', expiredCookie);
    res.cookie('inflow_claim', '', expiredCookie);
    // 只保存签名的随机会话标识与来源友链 ID，不含 IP/UA；30 分钟后自动失效。
    const attributionToken = jwt.sign(
      { type: 'inflow-attribution', visitId, sourcePartnerId: claim.partner_id },
      GUEST_JWT_SECRET,
      { expiresIn: ATTRIBUTION_TTL_SECONDS }
    );
    res.cookie(ATTRIBUTION_COOKIE, attributionToken, {
      maxAge: ATTRIBUTION_TTL_SECONDS * 1000,
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PRODUCTION,
      path: '/'
    });
    return ok(
      res,
      { newlyCounted, autoApproved },
      autoApproved ? '累计独立访客达到阈值，友链已自动审核通过'
        : newlyCounted ? '有效入站已计入积分' : '本周期已计分，本次仅记录访问行为'
    );
  } catch (error) {
    console.error('延迟心跳确认失败：', error.message);
    return fail(res, '延迟心跳确认失败', 500);
  }
}

function deprecatedInflowClaim(req, res) {
  return fail(res, '旧版入站认领接口已停用，请使用延迟心跳接口', 410);
}

async function getPublicConfig(req, res) {
  try {
    const cached = CacheService.getCachedData('public_config_data');
    if (cached) return res.json(cached);
    const contactInfo = await SystemModel.configValue('contact_info');
    const contactEmail = await SystemModel.configValue('contact_email') || await SystemModel.configValue('lost_prevention_email');
    const payload = {
      code: 200,
      msg: '操作成功',
      data: {
        site_name: await SystemModel.configValue('site_name'),
        site_logo_url: await SystemModel.configValue('site_logo_url'),
        site_url: await SystemModel.configValue('site_url'),
        admin_contact: contactInfo || await SystemModel.configValue('admin_contact'),
        contact_info: contactInfo,
        publish_url: await SystemModel.configValue('publish_url'),
        contact_email: contactEmail,
        lost_prevention_email: contactEmail,
        publish_modal_enabled: await SystemModel.configValue('publish_modal_enabled')
      }
    };
    CacheService.setCachedData('public_config_data', payload);
    return res.json(payload);
  } catch {
    return fail(res, '获取站点配置失败', 500);
  }
}

async function getCategories(req, res) {
  try { return ok(res, await SystemModel.listCategories()); }
  catch { return fail(res, '获取站点分类失败', 500); }
}

async function getMirrors(req, res) {
  try {
    const now = Date.now();
    if (mirrorsCache.data && mirrorsCache.expireTime > now) {
      return ok(res, mirrorsCache.data);
    }

    const [rows, mainUrl, contactEmail, legacyEmail, siteName, siteLogoUrl] = await Promise.all([
      MirrorModel.getEnabledMirrors(),
      SystemModel.configValue('site_url'),
      SystemModel.configValue('contact_email'),
      SystemModel.configValue('lost_prevention_email'),
      SystemModel.configValue('site_name'),
      SystemModel.configValue('site_logo_url')
    ]);
    const nodes = rows
      .map(row => ({ id: String(row.url), name: String(row.speed_name || '').trim(), partner_name: String(row.partner_name || '').trim(), url: String(row.url || '').trim() }))
      .filter(row => row.name && /^https?:\/\//i.test(row.url));
    const mainSite = /^https?:\/\//i.test(String(mainUrl || ''))
      ? { id: 'main-site', name: '主站官方入口', url: String(mainUrl).trim().replace(/\/$/, '') }
      : null;
    const mirrors = nodes.filter(node => node.url.replace(/\/$/, '') !== mainSite?.url);
    const payload = {
      // nodes 供首页节点切换器使用；mainSite/mirrors 保持永久发布页的既有接口兼容。
      nodes: [...(mainSite ? [mainSite] : []), ...nodes],
      site_name: siteName,
      site_logo_url: siteLogoUrl,
      contact_email: contactEmail,
      lost_prevention_email: contactEmail || legacyEmail,
      mainSite,
      mirrors
    };
    mirrorsCache = { data: payload, expireTime: now + MIRRORS_CACHE_TTL_MS };
    return ok(res, payload);
  } catch (error) {
    console.error('读取镜像节点失败：', error.message);
    return fail(res, '获取镜像节点列表失败', 500);
  }
}

function getCaptcha(req, res) {
  const captcha = svgCaptcha.create({
    size: 4,
    ignoreChars: '',
    noise: 2,
    color: true,
    background: '#ffffff',
    charPreset: '0123456789',
    width: 118,
    height: 42,
    fontSize: 36
  });
  req.session.captcha = captcha.text;
  return res.type('svg').status(200).send(captcha.data);
}

async function applyLink(req, res) {
  let normalizedDomain = '';
  let configuredSiteUrl = '';
  try {
    const { name, url, category, description = '', contact = '', captcha } = req.body || {};
    const expectedCaptcha = req.session.captcha;
    req.session.captcha = null;
    if (![name, url, category, captcha].every(value => String(value || '').trim())) {
      return fail(res, '请完整填写网站名称、网站分类、友链地址和验证码');
    }
    if (!/^\d{4}$/.test(String(captcha).trim()) || String(captcha).trim() !== expectedCaptcha) {
      return fail(res, '验证码错误或已过期');
    }
    const { url: cleanUrl, domain } = normalizePartnerUrl(url);
    normalizedDomain = domain;
    if (String(name).trim().length > 80 || String(description).trim().length > 200 || String(contact).trim().length > 200) {
      return fail(res, '填写内容过长，请精简后重试');
    }
    if (!(await SystemModel.categoryExists(String(category).trim()))) return fail(res, '请选择有效的网站分类');
    configuredSiteUrl = await SystemModel.configValue('site_url');
    const existing = await PartnerModel.findSubmissionByDomain(domain);
    if (existing) {
      const token = existing.source_sid ? { sid: existing.source_sid } : await SourceTokenModel.ensurePartnerSid(existing.id);
      const sourceUrls = buildSourceEntryUrls(token.sid, configuredSiteUrl);
      return res.status(200).json({
        code: 200,
        msg: '申请成功，请在贵站添加本站友链等待激活！',
        data: {
          id: existing.id,
          domain: existing.domain,
          source_sid: token.sid,
          source_links: { path: sourceUrls.pathUrl, query: sourceUrls.queryUrl }
        }
      });
    }
    const result = await PartnerModel.createPendingPartner({
      name: String(name).trim(),
      domain,
      url: cleanUrl,
      description: String(description).trim(),
      contact: String(contact).trim(),
      category: String(category).trim()
    });
    const sourceUrls = buildSourceEntryUrls(result.sourceSid, configuredSiteUrl);
    const contactForAlert = String(contact).replace(/[\r\n\t]+/g, ' ').trim();
    void sendAdminAlert(
      '🆕 新友链申请',
      [
        `站点名称：${String(name).trim()}`,
        `站点域名：${formatAlertLink(domain, domain, { allowDomain: true })}`,
        `站点网址：${formatAlertLink(cleanUrl, cleanUrl)}`,
        `反链检测网址：${formatAlertLink(cleanUrl, cleanUrl)}`,
        '说明：未单独配置，默认检测站点网址',
        `所属分类：${String(category).trim()}`,
        formatContactLine('友链站长联系方式', contactForAlert),
        `专属路径地址：${formatAlertLink(sourceUrls.pathUrl, sourceUrls.pathUrl)}`,
        `专属参数地址：${formatAlertLink(sourceUrls.queryUrl, sourceUrls.queryUrl)}`,
        `提交时间：${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })}`
      ].join('\n'),
      {
        eventType: 'new_partner_apply',
        barkUrl: cleanUrl,
        barkCopy: contactForAlert
      }
    );
    return res.status(200).json({
      code: 200,
      msg: '申请成功，请在贵站添加本站友链等待激活！',
      data: {
        id: result.id,
        domain,
        source_sid: result.sourceSid,
        source_links: {
          path: sourceUrls.pathUrl,
          query: sourceUrls.queryUrl
        }
      }
    });
  } catch (error) {
    console.error('提交友链申请失败：', error);
    if (isUniqueConstraintError(error) && normalizedDomain) {
      try {
        const existing = await PartnerModel.findSubmissionByDomain(normalizedDomain);
        if (existing) {
          const token = existing.source_sid ? { sid: existing.source_sid } : await SourceTokenModel.ensurePartnerSid(existing.id);
          const sourceUrls = buildSourceEntryUrls(token.sid, configuredSiteUrl);
          return res.status(200).json({
            code: 200,
            msg: '申请成功，请在贵站添加本站友链等待激活！',
            data: {
              id: existing.id,
              domain: existing.domain,
              source_sid: token.sid,
              source_links: { path: sourceUrls.pathUrl, query: sourceUrls.queryUrl }
            }
          });
        }
      } catch (lookupError) {
        console.error('读取重复申请的专属地址失败：', lookupError);
      }
    }
    return fail(res, safeApiErrorMessage(error), 500);
  }
}

async function getLinks(req, res) {
  try {
    const cached = CacheService.getCachedData('public_links_data');
    if (cached) return res.json(cached);
    const [categories, linkLists] = await Promise.all([
      SystemModel.listCategories(),
      PartnerModel.getPublicLists()
    ]);
    const payload = {
      code: 200,
      msg: '操作成功',
      data: { categories, hotList: linkLists.hotList, links: linkLists.links }
    };
    CacheService.setCachedData('public_links_data', payload);
    return res.json(payload);
  } catch {
    return fail(res, '获取友链列表失败', 500);
  }
}

async function getLinkDetail(req, res) {
  try {
    const linkId = Number.parseInt(String(req.params.id || ''), 10);
    if (!Number.isSafeInteger(linkId) || linkId <= 0) return fail(res, '站点编号不合法');
    const cacheKey = `public_link_detail_${linkId}`;
    const cached = CacheService.getCachedData(cacheKey);
    if (cached) return res.json(cached);
    const site = await PartnerModel.getPublicDetail(linkId);
    if (!site) return fail(res, '站点不存在、尚未审核或暂不可用', 404);
    const recommendations = await PartnerModel.getRecommendations(linkId, site.category);
    const payload = { code: 200, msg: '操作成功', data: { site, recommendations } };
    CacheService.setCachedData(cacheKey, payload);
    return res.json(payload);
  } catch (error) {
    console.error('获取站点详情失败：', error.message);
    return fail(res, '获取站点详情失败', 500);
  }
}

function detectShowcaseDevice(req) {
  const userAgent = String(req.get('user-agent') || '');
  if (/HarmonyOS|OpenHarmony/i.test(userAgent)) return 'harmony';
  if (/Android/i.test(userAgent)) return 'android';
  if (/iPhone|iPad|iPod/i.test(userAgent)) return 'ios';
  return 'pc';
}

function matchesShowcasePlatform(platform, device) {
  if (platform === 'all') return true;
  if (platform === 'non_ios') return device !== 'ios';
  return platform === device;
}

async function getAds(req, res) {
  try {
    const device = detectShowcaseDevice(req);
    const cacheKey = `public_showcase_data_${device}`;
    const cached = CacheService.getCachedData(cacheKey);
    if (cached) return res.json(cached);
    const rows = await AdModel.getActiveAds();
    const regularItems = rows
      .filter(row => row.ad_type === 'normal'
        && ['banner', 'icon'].includes(row.ad_position)
        && matchesShowcasePlatform(row.platform, device))
      .map(row => ({
        id: row.id,
        title: row.title,
        ad_type: row.ad_type,
        ad_position: row.ad_position,
        platform: row.platform,
        target_url: row.target_url || '',
        image_url: row.image_url || '',
        description: row.description || '',
        sort_order: Number(row.sort_order || 0)
      }));
    const codeItems = position => rows
      .filter(row => row.ad_type === 'code' && row.ad_position === position)
      .map(row => ({
        id: row.id,
        title: row.title,
        ad_type: 'code',
        ad_position: row.ad_position,
        platform: 'all',
        ad_code: row.ad_code || '',
        markup: row.ad_code || '',
        sort_order: Number(row.sort_order || 0)
      }));
    const payload = {
      code: 200,
      msg: '操作成功',
      data: {
        device,
        regularItems,
        topFloatItems: codeItems('top_float'),
        bottomFloatItems: codeItems('bottom_float'),
        iconFloatItems: codeItems('icon_float')
      }
    };
    CacheService.setCachedData(cacheKey, payload);
    return res.json(payload);
  } catch (error) {
    console.error('获取公开广告失败：', error);
    return fail(res, '获取广告失败', 500);
  }
}

function normalizeShowcaseDiagnosticHost(value) {
  const host = String(value || '').trim().toLowerCase();
  return /^[a-z0-9.-]{1,253}$/.test(host) ? host : '';
}

function normalizeShowcaseDiagnosticEvent(value) {
  const adId = Number(value?.adId);
  const phase = String(value?.phase || '');
  const bootstrapStatus = String(value?.bootstrapStatus || '');
  const externalStatus = String(value?.externalStatus || '');
  if (!Number.isSafeInteger(adId) || adId <= 0
    || !SHOWCASE_DIAGNOSTIC_PHASES.has(phase)
    || !AdModel.RUNTIME_STATUSES.has(bootstrapStatus)
    || !AdModel.RUNTIME_STATUSES.has(externalStatus)) return null;
  return {
    adId,
    phase,
    providerHost: normalizeShowcaseDiagnosticHost(value?.providerHost),
    bootstrapStatus,
    externalStatus,
    externalScriptCount: Math.min(20, Math.max(0, Number.parseInt(value?.externalScriptCount, 10) || 0)),
    externalFailedCount: Math.min(20, Math.max(0, Number.parseInt(value?.externalFailedCount, 10) || 0)),
    slow: value?.slow === true || value?.slow === 1 || value?.slow === '1',
    durationMs: Math.min(30000, Math.max(0, Number.parseInt(value?.durationMs, 10) || 0)),
    startedAt: Math.min(Date.now(), Math.max(0, Number.parseInt(value?.startedAt, 10) || 0))
  };
}

/** 代码广告的浏览器侧运行诊断：仅接收受限状态字段，不接收联盟源码或访客内容。 */
async function recordShowcaseDiagnostics(req, res) {
  try {
    const candidates = (Array.isArray(req.body?.events) ? req.body.events : [])
      .slice(0, 3)
      .map(normalizeShowcaseDiagnosticEvent)
      .filter(Boolean);
    if (!candidates.length) return res.status(204).end();

    const activeAds = await AdModel.getActiveCodeAdsByIds(candidates.map(event => event.adId));
    const activeById = new Map(activeAds.map(ad => [ad.id, ad]));
    const events = candidates.filter(event => activeById.get(event.adId)?.ad_position === event.phase);
    if (events.length) await AdModel.recordRuntimeEvents(events);
    return res.status(204).end();
  } catch (error) {
    // 诊断上报绝不能影响页面；sendBeacon 调用方无需等待此响应。
    console.warn('[Showcase] 保存代码广告运行诊断失败：', error.message);
    return res.status(204).end();
  }
}

async function go(req, res) {
  try {
    const linkId = Number.parseInt(String(req.query.id || ''), 10);
    if (!Number.isSafeInteger(linkId) || linkId <= 0) return fail(res, '友链编号不合法');
    const link = await PartnerModel.getApprovedOutboundTarget(linkId);
    if (!link) return fail(res, '友链不存在或尚未审核通过', 404);
    const clientIp = getClientIp(req) || '127.0.0.1';
    const attribution = readAttributionVisit(req);
    try {
      await dbMutex.runExclusive(() => LogModel.recordOutbound(link.id, clientIp, attribution || {}));
    } catch (error) {
      console.error('[Outbound Track Error]:', error.message);
    }
    return res.redirect(302, link.url);
  } catch (error) {
    console.error('出站跳转记录失败：', error.message);
    return fail(res, '出站跳转失败，请稍后重试', 500);
  }
}

module.exports = {
  preVerifyInflowTraffic,
  trackInflow,
  health,
  headRoot,
  favicon,
  initVerification,
  checkVerification,
  getAnalyticsConfig,
  getInflowToken,
  trackPing,
  deprecatedInflowClaim,
  getPublicConfig,
  getCategories,
  getMirrors,
  clearMirrorsCache,
  getCaptcha,
  applyLink,
  getLinks,
  getLinkDetail,
  getAds,
  recordShowcaseDiagnostics,
  go
};
