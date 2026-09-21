'use strict';

const crypto = require('crypto');
const path = require('path');
const { dbWriteCoordinator } = require('../services/DbWriteCoordinator');
const { get: databaseGet } = require('../config/database');
const jwt = require('jsonwebtoken');
const svgCaptcha = require('svg-captcha');
const { Mutex } = require('async-mutex');
const {
  IS_PRODUCTION,
  GUEST_JWT_SECRET,
  TRAFFIC_DEBUG,
  PUBLIC_CODE_ADS_ENABLED,
  BROWSER_ACCESS_TTL_MS
} = require('../config/env');
const { getClientIp, parseHostname, normalizePartnerUrl, normalizeRegisteredDomain } = require('../utils/network');
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
  storeVerificationNonce,
  getVerificationNonce,
  consumeVerificationNonce
} = require('../middlewares/rateLimit');
const { issueReadAccessToken } = require('../middlewares/readAccess');
const PartnerModel = require('../models/PartnerModel');
const SourceTokenModel = require('../models/SourceTokenModel');
const LogModel = require('../models/LogModel');
const SystemModel = require('../models/SystemModel');
const AdModel = require('../models/AdsModel');
const MirrorModel = require('../models/MirrorModel');
const CacheService = require('../services/CacheService');
const SiteTrafficService = require('../services/SiteTrafficService');
const PartnerPageViewService = require('../services/PartnerPageViewService');
const InflowAttributionService = require('../services/InflowAttributionService');
const VisitorRiskService = require('../services/VisitorRiskService');
const ReadProofService = require('../services/ReadProofService');
const BotRiskClient = require('../services/BotRiskClient');
const BrowserChallengeService = require('../services/BrowserChallengeService');
const InflowService = require('../services/InflowService');
const IpIntelligenceService = require('../services/IpIntelligenceService');
const { sendAdminAlert, formatAlertLink, formatContactLine } = require('../services/AlertService');

const ATTRIBUTION_COOKIE = 'inflow_visit';
const ATTRIBUTION_TTL_SECONDS = 30 * 60;
const ROUTE_HEALTH_GIF = Buffer.from(
  'R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==',
  'base64'
);
const ANALYTICS_CONFIG_KEYS = [
  'umami_enabled',
  'umami_script_url',
  'umami_website_id',
  'cf_analytics_enabled',
  'cf_beacon_token',
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

function visitorIdentityHash(req) {
  const identity = String(req.visitorId || '').trim();
  return identity ? crypto.createHash('sha256').update(identity).digest('hex') : '';
}

function normalizeClientEnvironment(userAgent, fingerprint = {}) {
  const resolutionInput = String(fingerprint.resolution || '').trim();
  const screenResolution = /^\d{1,5}x\d{1,5}$/i.test(resolutionInput) ? resolutionInput.slice(0, 32) : '';
  const clientLanguage = String(fingerprint.language || '').replace(/[^a-z0-9_-]/gi, '').slice(0, 32);
  const clientPlatform = String(fingerprint.platform || '').replace(/[\r\n\t]+/g, ' ').trim().slice(0, 80);
  const hasEnvironment = Boolean(screenResolution || clientLanguage || clientPlatform);
  const clientFingerprint = hasEnvironment
    ? crypto.createHash('sha256')
      .update([String(userAgent || ''), screenResolution, clientLanguage, clientPlatform].join('\n'))
      .digest('hex')
    : '';
  return { screenResolution, clientLanguage, clientPlatform, clientFingerprint };
}

function queueRejectedInbound(req, details = {}) {
  const clientIp = getClientIp(req);
  if (!clientIp) return;
  const referer = details.referer ?? String(req.get('Referer') || req.get('Referrer') || '').trim();
  void LogModel.recordRejectedInbound({
    clientIp,
    visitorHash: visitorIdentityHash(req),
    userAgent: String(details.userAgent ?? req.get('user-agent') ?? '').trim(),
    referer,
    observedDomain: details.observedDomain ?? normalizeRegisteredDomain(parseHostname(referer)),
    partnerId: details.partnerId,
    sourceTokenId: details.sourceTokenId,
    attributionMethod: details.attributionMethod,
    visitorType: details.visitorType || 'source_validation',
    stage: details.stage || 'source',
    reasonCode: details.reasonCode || 'unknown',
    reasonText: details.reasonText || '未通过入站校验',
    attemptId: details.attemptId,
    classification: details.classification,
    requestPath: String(req.originalUrl || req.path || '/').slice(0, 500)
  }).then(() => {
    IpIntelligenceService.queueIp(clientIp);
  }).catch(error => console.error('[未入站记录失败]：', error.message));
}

function readAttributionVisit(req) {
  const token = decodeURIComponent(getCookie(req, ATTRIBUTION_COOKIE) || '');
  if (token) {
    try {
      const payload = jwt.verify(token, GUEST_JWT_SECRET);
      if (payload?.type === 'inflow-attribution'
        && typeof payload.visitId === 'string'
        && Number.isSafeInteger(Number(payload.sourcePartnerId))) {
        return { visitId: payload.visitId, sourcePartnerId: Number(payload.sourcePartnerId) };
      }
    } catch {
      // Cookie 可能被代理、缓存或旧浏览器策略影响；继续使用同访客的短期服务端备份。
    }
  }
  return InflowAttributionService.recall(req.visitorId || '');
}

function readAttributionToken(token) {
  try {
    const payload = jwt.verify(String(token || ''), GUEST_JWT_SECRET, { algorithms: ['HS256'] });
    if (payload?.type !== 'inflow-attribution'
      || typeof payload.visitId !== 'string'
      || !Number.isSafeInteger(Number(payload.sourcePartnerId))) return null;
    return { visitId: payload.visitId, sourcePartnerId: Number(payload.sourcePartnerId) };
  } catch {
    return null;
  }
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
  return InflowService.resolveSourceAttribution({
    sourceSidPresent: true,
    sourceSid: sidInput.value,
    referer
  });
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
      ensureVisitorIdentity(req, res);
      const source = await resolveSidLanding(req);
      // 每次 SID 落地都覆盖旧归属；无效 SID 也必须清掉历史 Cookie，避免陈旧来源串号。
      clearPendingTrafficReferer(res);
      if (source?.partnerId) storePendingTrafficSource(req, res, source);
      else {
        clearPendingTrafficSource(res);
        queueRejectedInbound(req, {
          referer: source?.referer || '',
          observedDomain: source?.observedDomain || '',
          sourceTokenId: source?.sourceTokenId || null,
          attributionMethod: source?.method || 'invalid_sid',
          stage: 'sid_resolution',
          reasonCode: 'invalid_sid',
          reasonText: 'SID 不存在、已失效或无法归属到友链'
        });
      }
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

const SITE_TRAFFIC_EXCLUDED_PATH = /^(?:\/admin(?:\/|$)|\/api(?:\/|$)|\/go\/?$|\/verify(?:\.html)?\/?$)/i;
const SITE_TRAFFIC_ASSET_PATH = /\.(?:css|js|mjs|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|map|json|xml|txt|webmanifest)$/i;
const SITE_TRAFFIC_BOT_UA = /(?:bot|spider|crawl|slurp|headless|phantom|lighthouse|pagespeed|curl|wget|python|requests|postman|httpclient|scrapy|uptime|monitoring)/i;

/**
 * 独立记录成功打开的公开 HTML 页面。这里只向内存缓冲加一，不等待 SQLite；
 * 失败、后台、接口、验证页、静态资源、预取及明确机器人均不计入。
 */
function trackSitePageView(req, res, next) {
  try {
    const pathname = String(req.path || '/');
    const userAgent = String(req.get('user-agent') || '').trim();
    const fetchDestination = String(req.get('sec-fetch-dest') || '').toLowerCase();
    const purpose = `${req.get('purpose') || ''} ${req.get('sec-purpose') || ''} ${req.get('x-moz') || ''}`.toLowerCase();
    const eligible = req.method === 'GET'
      && !SITE_TRAFFIC_EXCLUDED_PATH.test(pathname)
      && !SITE_TRAFFIC_ASSET_PATH.test(pathname)
      && (!fetchDestination || fetchDestination === 'document')
      && !/(?:prefetch|prerender)/.test(purpose)
      && Boolean(userAgent)
      && !SITE_TRAFFIC_BOT_UA.test(userAgent);
    if (!eligible) return next();
    // 这里只签发稳定的匿名访客标识；PV 由页面加载后的专用接口记录，避免静态文档
    // 生命周期、缓存或代理差异导致 finish 事件漏记。
    ensureVisitorIdentity(req, res);
  } catch (error) {
    console.warn('[全站访客统计] 页面识别失败：', error.message);
  }
  return next();
}

function recordSitePageView(req, res) {
  const pagePath = String(req.body?.pagePath || '');
  if (!/^\/(?:index\.html|site-detail(?:\.html)?)?$/.test(pagePath)) {
    return fail(res, '页面地址不支持统计', 400);
  }
  const visitorId = ensureVisitorIdentity(req, res);
  const normalizedIp = getClientIp(req);
  if (!normalizedIp) return fail(res, '无法识别客户端 IP', 400);
  SiteTrafficService.recordPageView({ visitorId, normalizedIp, occurredAt: new Date() });
  return res.status(204).end();
}

function recordPostEntryPageView(req, res) {
  const attribution = readAttributionToken(req.body?.token);
  const pagePath = String(req.body?.pagePath || '');
  if (!attribution) return fail(res, '入站归因已失效', 401);
  if (!/^\/(?:index\.html|site-detail(?:\.html)?|publish\.html)?$/.test(pagePath)) {
    return fail(res, '页面地址不支持统计', 400);
  }
  PartnerPageViewService.recordPageView({
    partnerId: attribution.sourcePartnerId,
    visitId: attribution.visitId,
    occurredAt: new Date()
  });
  return res.status(204).end();
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

    const result = await InflowService.prepareLanding({
      clientIp: ip,
      userAgent: req.get('user-agent'),
      visitorHash: visitorIdentityHash(req),
      referer: effectiveReferer,
      requestPath: String(req.originalUrl || req.path || '/').slice(0, 500),
      frontendOrigin: `${req.protocol}://${req.get('host')}`,
      preResolvedSource: pendingSource
    });
    if (result.status === 'rejected') {
      trafficDebug(`拦截原因: ${result.reasonText}`);
      queueRejectedInbound(req, result);
      return next();
    }
    if (result.status === 'claim_issued') setInflowClaimCookies(res, result.token);
    return next();
  } catch (error) {
    console.error('[流量排查] 入站凭证签发失败：', error.message);
    return next();
  }
}

function setInflowClaimCookies(res, token) {
  const cookieOptions = {
    maxAge: InflowService.CLAIM_TTL_SECONDS * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PRODUCTION,
    path: '/'
  };
  res.cookie('track_session', token, cookieOptions);
  res.cookie('inflow_claim', token, cookieOptions);
}

/** 物理分离前台的可信边缘落地入口；只签发 Claim，绝不在这里增加带量。 */
async function prepareFrontendLanding(req, res) {
  try {
    const body = req.body || {};
    const requestPath = String(body.requestPath || '/').slice(0, 500);
    const supportedLanding = /^\/(?:\?.*)?$/.test(requestPath)
      || /^\/index\.html(?:\?.*)?$/.test(requestPath)
      || /^\/r\/[^/?]+\/?(?:\?.*)?$/.test(requestPath);
    if (!supportedLanding) {
      return fail(res, '落地页面地址不合法', 400);
    }
    const visitorId = ensureVisitorIdentity(req, res);
    const sourceSidPresent = body.sourceSid !== undefined && body.sourceSid !== null;
    const result = await InflowService.prepareLanding({
      clientIp: getClientIp(req),
      userAgent: String(body.userAgent || req.get('user-agent') || '').slice(0, 500),
      visitorHash: crypto.createHash('sha256').update(visitorId).digest('hex'),
      referer: String(body.referer || '').slice(0, 2048),
      sourceSidPresent,
      sourceSid: String(body.sourceSid || '').slice(0, 256),
      requestPath,
      frontendOrigin: req.trustedFrontendOrigin
    });
    res.set('Cache-Control', 'private, no-store');
    if (result.status === 'claim_issued') setInflowClaimCookies(res, result.token);
    else if (result.status === 'rejected') {
      queueRejectedInbound(req, {
        ...result,
        userAgent: String(body.userAgent || req.get('user-agent') || '').slice(0, 500)
      });
    }
    return ok(res, {
      status: result.status,
      claimIssued: result.status === 'claim_issued',
      cleanPath: sourceSidPresent ? '/' : null
    });
  } catch (error) {
    console.error('[Frontend Landing] 入站准备失败：', error.message);
    return fail(res, '入站准备失败', 500);
  }
}

function health(req, res) {
  return res.status(200).json({
    status: 'ok',
    timestamp: Date.now(),
    dbWriteQueue: dbWriteCoordinator.getStats()
  });
}

async function routeHealthGif(req, res) {
  try {
    const database = await databaseGet('SELECT 1 AS healthy');
    if (Number(database?.healthy) !== 1) throw new Error('database unavailable');
    res.set({
      'Content-Type': 'image/gif',
      'Content-Length': String(ROUTE_HEALTH_GIF.length),
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      Pragma: 'no-cache'
    });
    return res.status(200).end(ROUTE_HEALTH_GIF);
  } catch {
    res.set({
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store'
    });
    return res.status(503).send('unavailable');
  }
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

function getReadBootstrap(req, res) {
  const visitorId = ensureVisitorIdentity(req, res);
  const localRisk = VisitorRiskService.recordBootstrapSignals(visitorId, {
    fetchSite: req.get('sec-fetch-site'),
    fetchMode: req.get('sec-fetch-mode'),
    fetchDest: req.get('sec-fetch-dest'),
    origin: req.get('origin'),
    referer: req.get('referer'),
    userAgent: req.get('user-agent'),
    expectedOrigin: req.trustedFrontendOrigin || `${req.protocol}://${req.get('host')}`
  });
  if (localRisk?.signalFlags?.includes('script-user-agent')) {
    BotRiskClient.enqueue(visitorId, 'script_user_agent', { path: '/api/read/bootstrap' });
  }
  const centralDecision = BotRiskClient.getDecision(visitorId);
  if (centralDecision?.enforce && centralDecision.decision === 'deny') {
    res.set('Cache-Control', 'private, no-store');
    return res.status(403).json({ code: 403, msg: '请求无法处理', data: null });
  }
  const restriction = VisitorRiskService.getReadRestriction(visitorId);
  const centralChallenge = centralDecision?.enforce
    && ['silent_challenge', 'strong_challenge'].includes(centralDecision.decision)
    && !BotRiskClient.hasChallengeBypass(visitorId);
  if (restriction || centralChallenge) {
    const difficulty = centralDecision?.decision === 'strong_challenge' ? 16 : 12;
    res.set('Cache-Control', 'private, no-store');
    return res.status(428).json({
      code: 428,
      msg: IS_PRODUCTION ? '请求无法处理' : '当前读取会话需要完成短时计算校验',
      data: {
        proofRequired: true,
        challenge: ReadProofService.issueChallenge(visitorId, Date.now(), difficulty)
      }
    });
  }
  return ok(res, issueReadAccessToken(req, res), '读取凭证已生成');
}

function getBrowserChallenge(req, res) {
  const visitorId = ensureVisitorIdentity(req, res);
  const decision = BotRiskClient.getDecision(visitorId);
  res.set('Cache-Control', 'private, no-store');
  if (decision?.enforce && decision.decision === 'deny') {
    return res.status(403).json({ code: 403, msg: '请求无法处理', data: null });
  }
  return ok(res, {
    challenge: BrowserChallengeService.issue(visitorId, decision),
    mode: 'silent'
  }, '浏览器校验已初始化');
}

function verifyBrowserChallenge(req, res) {
  const visitorId = ensureVisitorIdentity(req, res);
  const body = req.body || {};
  const proof = BrowserChallengeService.verifyProof(visitorId, body);
  res.set('Cache-Control', 'private, no-store');
  if (!proof.ok) return fail(res, '浏览器校验无效或已过期', 400);

  const botD = body.botD && typeof body.botD === 'object' ? body.botD : {};
  const webdriver = body.webdriver === true;
  const botDetected = botD.bot === true;
  BotRiskClient.enqueue(visitorId, 'browser_challenge_passed', {
    elapsedMs: proof.elapsed,
    difficultyBits: proof.difficultyBits,
    webdriver,
    botDetected,
    botKind: String(botD.kind || '').slice(0, 64)
  });
  // 单一浏览器探针可能误报；仅在两个独立自动化信号同时出现时立即拒绝。
  if (BrowserChallengeService.isEnforced() && webdriver && botDetected) {
    BotRiskClient.enqueue(visitorId, 'browser_automation_confirmed');
    return fail(res, '请求无法处理', 403);
  }

  const token = BrowserChallengeService.issueAccessToken(
    visitorId,
    req.get('user-agent') || '',
    botDetected || webdriver ? 'observed' : 'browser'
  );
  res.cookie(BrowserChallengeService.COOKIE_NAME, token, {
    maxAge: BROWSER_ACCESS_TTL_MS,
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PRODUCTION,
    path: '/'
  });
  BotRiskClient.markChallengePassed(visitorId);
  return ok(res, { verified: true, expiresIn: Math.floor(BROWSER_ACCESS_TTL_MS / 1000) }, '浏览器校验通过');
}

function verifyReadProof(req, res) {
  const visitorId = ensureVisitorIdentity(req, res);
  const result = ReadProofService.verifyChallenge(visitorId, req.body || {});
  res.set('Cache-Control', 'private, no-store');
  if (!result.ok) {
    return res.status(400).json({
      code: 400,
      msg: IS_PRODUCTION ? '请求无法处理' : '计算校验无效或已过期',
      data: null
    });
  }
  VisitorRiskService.markReadProofVerified(visitorId);
  BotRiskClient.markChallengePassed(visitorId);
  return ok(res, { verified: true }, '计算校验通过');
}

function recordTrapdoor(req, res) {
  const visitorId = ensureVisitorIdentity(req, res);
  const record = VisitorRiskService.recordTrapdoor(visitorId, {
    userAgent: req.get('user-agent'),
    path: req.originalUrl || req.path
  });
  BotRiskClient.enqueue(visitorId, record?.repeatedQuickly ? 'repeated_trapdoor' : 'trapdoor_hit', {
    path: String(req.originalUrl || req.path).slice(0, 200)
  });
  if (TRAFFIC_DEBUG && record) {
    console.warn(`[访客风险] 隐藏探针命中：visitor=${visitorId.slice(0, 8)}… score=${record.score} hits=${record.trapHits}`);
  }
  res.set('Cache-Control', 'private, no-store');
  return res.status(204).end();
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
    if (!cookieToken || (suppliedToken && suppliedToken !== cookieToken)) {
      if (cookieToken || suppliedToken) queueRejectedInbound(req, {
        stage: 'heartbeat', reasonCode: 'claim_token_mismatch',
        reasonText: '追踪会话不匹配或已过期'
      });
      return fail(res, '追踪会话无效或已过期', 401);
    }
    const tokenHash = crypto.createHash('sha256').update(cookieToken).digest('hex');
    const claim = await LogModel.getActiveClaim(tokenHash);
    if (!claim) return fail(res, '追踪会话已使用或已过期', 409);
    if (!claim.started_at_ms || Date.now() - Number(claim.started_at_ms) < 3000) {
      queueRejectedInbound(req, {
        referer: claim.referer, observedDomain: claim.observed_domain, partnerId: claim.partner_id,
        sourceTokenId: claim.source_token_id, attributionMethod: claim.attribution_method,
        attemptId: claim.attempt_id,
        stage: 'heartbeat', reasonCode: 'stay_too_short', reasonText: '页面停留时间不足3秒'
      });
      return fail(res, '停留时间不足，暂不计入带量', 429);
    }
    const clientIp = getClientIp(req);
    const ua = String(req.get('user-agent') || '').trim();
    if (clientIp !== claim.ip || !ua || /curl|python|requests|headlesschrome|postman|wget|httpclient|scrapy|bot|spider|crawl|slurp/i.test(ua)) {
      queueRejectedInbound(req, {
        referer: claim.referer, observedDomain: claim.observed_domain, partnerId: claim.partner_id,
        sourceTokenId: claim.source_token_id, attributionMethod: claim.attribution_method,
        attemptId: claim.attempt_id,
        stage: 'heartbeat', reasonCode: 'environment_mismatch', reasonText: 'IP、User-Agent 或访问环境校验未通过'
      });
      return fail(res, '访问环境校验未通过', 403);
    }

    const fingerprint = body.fingerprint && typeof body.fingerprint === 'object' ? body.fingerprint : {};
    const compliant = fingerprint.webdriver !== true && fingerprint.abnormalScreen !== true && fingerprint.missingLanguage !== true;
    if (!compliant) {
      queueRejectedInbound(req, {
        referer: claim.referer, observedDomain: claim.observed_domain, partnerId: claim.partner_id,
        sourceTokenId: claim.source_token_id, attributionMethod: claim.attribution_method,
        attemptId: claim.attempt_id,
        stage: 'fingerprint', reasonCode: 'abnormal_fingerprint', reasonText: '浏览器指纹或自动化环境异常'
      });
      return fail(res, '访问环境校验未通过', 403);
    }
    const clientEnvironment = normalizeClientEnvironment(ua, fingerprint);
    const visitId = crypto.randomUUID();
    const transactionResult = await dbMutex.runExclusive(() => LogModel.processTrackPing({
      tokenHash,
      claim,
      clientIp,
      userAgent: ua,
      visitId,
      visitorHash: claim.visitor_hash || visitorIdentityHash(req),
      ...clientEnvironment
    }));
    if (transactionResult.alreadyUsed) {
      queueRejectedInbound(req, {
        referer: claim.referer, observedDomain: claim.observed_domain, partnerId: claim.partner_id,
        sourceTokenId: claim.source_token_id, attributionMethod: claim.attribution_method,
        attemptId: claim.attempt_id,
        stage: 'database_write', reasonCode: 'claim_already_used', reasonText: '追踪会话已被使用'
      });
      return fail(res, '追踪会话已使用', 409);
    }
    const { newlyCounted, autoApproved } = transactionResult;
    const attribution = { visitId, sourcePartnerId: Number(claim.partner_id) };
    PartnerPageViewService.recordConfirmedEntry({
      partnerId: attribution.sourcePartnerId,
      visitId: attribution.visitId,
      occurredAt: new Date()
    });
    // Cookie 是跨重启的第一归属凭证；该短期备份仅补偿部分浏览器/代理未回传 Cookie 的情况。
    InflowAttributionService.remember(ensureVisitorIdentity(req, res), attribution);
    IpIntelligenceService.queueIp(clientIp);
    if (newlyCounted || autoApproved) CacheService.clearPublicCache();
    const expiredCookie = { maxAge: 0, httpOnly: true, sameSite: 'lax', secure: IS_PRODUCTION, path: '/' };
    res.cookie('track_session', '', expiredCookie);
    res.cookie('inflow_claim', '', expiredCookie);
    // 只保存签名的随机会话标识与来源友链 ID，不含 IP/UA；30 分钟后自动失效。
    const attributionToken = jwt.sign(
      { type: 'inflow-attribution', visitId: attribution.visitId, sourcePartnerId: attribution.sourcePartnerId },
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
      { newlyCounted, autoApproved, attributionToken },
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
    // 任意第三方 JavaScript 不能与主站会话处于同一 Origin。默认不下发，
    // 仅在完成独立受限广告域部署后由环境变量显式恢复。
    const codeItems = position => !PUBLIC_CODE_ADS_ENABLED ? [] : rows
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
  prepareFrontendLanding,
  trackSitePageView,
  recordSitePageView,
  recordPostEntryPageView,
  trackInflow,
  health,
  routeHealthGif,
  headRoot,
  favicon,
  initVerification,
  getReadBootstrap,
  getBrowserChallenge,
  verifyBrowserChallenge,
  verifyReadProof,
  recordTrapdoor,
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
