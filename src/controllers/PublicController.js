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
const { getClientIp, parseHostname, matchesPartnerDomain, normalizePartnerUrl, normalizeRegisteredDomain, normalizeSourceMarker } = require('../utils/network');
const { normalizeUrl } = require('../utils/url');
const { ok, fail, safeApiErrorMessage, isUniqueConstraintError } = require('../utils/http');
const {
  VERIFY_NONCE_TTL_MS,
  VERIFY_COOKIE_TTL_MS,
  GUEST_VERIFY_COOKIE,
  storePendingTrafficReferer,
  readPendingTrafficReferer,
  clearPendingTrafficReferer,
  getCookie,
  isPartnerVisitRateLimited,
  storeVerificationNonce,
  getVerificationNonce,
  consumeVerificationNonce
} = require('../middlewares/rateLimit');
const PartnerModel = require('../models/PartnerModel');
const LogModel = require('../models/LogModel');
const SystemModel = require('../models/SystemModel');
const AdModel = require('../models/AdsModel');
const MirrorModel = require('../models/MirrorModel');
const CacheService = require('../services/CacheService');
const { sendAdminAlert } = require('../services/AlertService');

const CLAIM_TTL_SECONDS = 15 * 60;
const ATTRIBUTION_COOKIE = 'inflow_visit';
const ATTRIBUTION_TTL_SECONDS = 30 * 60;
const ANALYTICS_CONFIG_KEYS = [
  'umami_enabled',
  'umami_script_url',
  'umami_website_id',
  'cf_analytics_enabled',
  'cf_beacon_token'
];
const dbMutex = new Mutex();
const MIRRORS_CACHE_TTL_MS = 60 * 1000;
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

async function isLegitUser(req, refererOverride = '') {
  const ua = String(req.headers['user-agent'] || '').trim();
  const invalidUa = /curl|python|requests|headlesschrome|postman|wget|httpclient|scrapy|bot|spider|crawl|slurp/i;
  if (!ua || invalidUa.test(ua)) {
    req.trafficBlockReason = '爬虫、无头浏览器或异常 User-Agent';
    return false;
  }

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

/**
 * 滑块门禁之前仅保存短效来源凭证。
 * 严禁在这里查询 24h 去重或写入 inbound_logs；正式计分只由 trackPing 完成。
 */
async function preVerifyInflowTraffic(req, res, next) {
  try {
    if (req.method !== 'GET' || req.path !== '/') return next();
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
    const requestReferer = String(req.get('Referer') || '').trim();
    const restoredReferer = readPendingTrafficReferer(req);
    const effectiveReferer = restoredReferer || requestReferer;
    if (restoredReferer) clearPendingTrafficReferer(res);

    if (!ip || !(await isLegitUser(req, effectiveReferer))) {
      trafficDebug(`拦截原因: ${req.trafficBlockReason || '无法识别客户端 IP'}`);
      return next();
    }

    const refererUrl = new URL(effectiveReferer);
    const domain = normalizeRegisteredDomain(refererUrl.hostname);
    const candidates = await PartnerModel.listInflowCandidates();
    // 兼容历史上曾保存子域名的记录；新写入统一使用可注册主域名。
    const partner = candidates.find(item => domain === normalizeRegisteredDomain(item.domain));
    const markerPartner = partner || candidates.find(item => {
      const marker = normalizeSourceMarker(item.source_marker);
      return marker.length >= 4 && effectiveReferer.includes(marker);
    });
    if (!markerPartner) {
      return next();
    }
    const now = Date.now();
    if (isPartnerVisitRateLimited(markerPartner.id, ip)) {
      return next();
    }

    const token = crypto.randomBytes(24).toString('base64url');
    await LogModel.createClaimToken({
      tokenHash: crypto.createHash('sha256').update(token).digest('hex'),
      partnerId: markerPartner.id,
      ip,
      ttlSeconds: CLAIM_TTL_SECONDS,
      startedAtMs: now,
      referer: effectiveReferer
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
  const nonce = crypto.randomBytes(16).toString('hex');
  const issuedAt = Date.now();
  const rawData = `${nonce}-${issuedAt}`;
  const sign = crypto.createHmac('sha256', GUEST_JWT_SECRET).update(rawData).digest('hex');
  storeVerificationNonce(nonce, {
    issuedAt,
    expiresAt: issuedAt + VERIFY_NONCE_TTL_MS,
    ip: getClientIp(req),
    ua: String(req.get('user-agent') || '').slice(0, 300)
  });
  const token = `${rawData}.${sign}`;
  return res.json({ code: 200, msg: '验证令牌已生成', data: { token, expiresIn: 60 }, success: true, token });
}

function checkVerification(req, res) {
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
  if (record.ip !== getClientIp(req) || record.ua !== String(req.get('user-agent') || '').slice(0, 300)) {
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
    { scope: 'guest-verified', role: 'guest', type: 'guest-verification' },
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

    const [rows, mainUrl, contactEmail, legacyEmail] = await Promise.all([
      MirrorModel.getEnabledMirrors(),
      SystemModel.configValue('site_url'),
      SystemModel.configValue('contact_email'),
      SystemModel.configValue('lost_prevention_email')
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
    background: '#0d1b2a',
    charPreset: '0123456789',
    width: 118,
    height: 42,
    fontSize: 36
  });
  req.session.captcha = captcha.text;
  return res.type('svg').status(200).send(captcha.data);
}

async function applyLink(req, res) {
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
    if (String(name).trim().length > 80 || String(description).trim().length > 200 || String(contact).trim().length > 200) {
      return fail(res, '填写内容过长，请精简后重试');
    }
    if (!(await SystemModel.categoryExists(String(category).trim()))) return fail(res, '请选择有效的网站分类');
    const result = await PartnerModel.createPendingPartner({
      name: String(name).trim(),
      domain,
      url: cleanUrl,
      description: String(description).trim(),
      contact: String(contact).trim(),
      category: String(category).trim()
    });
    void sendAdminAlert(
      '🆕 新友链申请',
      `> **站点名称：** ${String(name).trim()}\n> **网站 URL：** ${cleanUrl}\n> **所属分类：** ${String(category).trim()}\n> **联系方式：** ${String(contact).trim() || '未填写'}\n> **提交时间：** ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`
    );
    return res.status(200).json({
      code: 200,
      msg: '申请成功，请在贵站添加本站友链等待激活！',
      data: { id: result.id, domain }
    });
  } catch (error) {
    console.error('提交友链申请失败：', error);
    if (isUniqueConstraintError(error)) return fail(res, '该友链域名已提交，请勿重复申请', 409);
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
  go
};
