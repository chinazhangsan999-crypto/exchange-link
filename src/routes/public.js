'use strict';

const express = require('express');
const PublicController = require('../controllers/PublicController');
const {
  createRateLimiter,
  createVisitorRateLimiter,
  applyRiskProtection,
  outboundRiskProtection,
  adaptiveVerificationGate
} = require('../middlewares/rateLimit');
const { requireReadAccess } = require('../middlewares/readAccess');
const { limitReadConcurrency } = require('../middlewares/readConcurrency');
const {
  requireTrustedFrontendProxy,
  requireFrontendProxy
} = require('../middlewares/frontendProxy');

const router = express.Router();
const captchaRateLimiter = createRateLimiter('captcha', 60 * 60 * 1000, 20);
const trackPingRateLimiter = createVisitorRateLimiter('track-ping', 10 * 1000, 3, 300);
const postEntryPageViewRateLimiter = createVisitorRateLimiter('post-entry-page-view', 60 * 1000, 60, 600);
const sitePageViewRateLimiter = createVisitorRateLimiter('site-page-view', 60 * 1000, 120, 1200);
const verifyInitRateLimiter = createRateLimiter('verify-init', 10 * 60 * 1000, 20);
const verifyCheckRateLimiter = createRateLimiter('verify-check', 10 * 60 * 1000, 10);
const showcaseDiagnosticRateLimiter = createRateLimiter('showcase-diagnostics', 60 * 1000, 20);
const readBootstrapRateLimiter = createVisitorRateLimiter('read-bootstrap', 60 * 1000, 6, 600);
const readProofRateLimiter = createVisitorRateLimiter('read-proof', 60 * 1000, 6, 600);

router.get('/api/health', PublicController.health);
router.get('/.well-known/route-health.gif', PublicController.routeHealthGif);
// 仅供经过 HMAC 验签的静态前端边缘代理调用；浏览器无法直接伪造来源或客户端 IP。
router.post('/internal/frontend/landing', requireTrustedFrontendProxy, PublicController.prepareFrontendLanding);
router.use(requireFrontendProxy);
router.get('/api/read/bootstrap', readBootstrapRateLimiter, PublicController.getReadBootstrap);
router.post('/api/read/proof', readProofRateLimiter, PublicController.verifyReadProof);
router.get('/api/sys-trap/trapdoor', PublicController.recordTrapdoor);
router.head('/', PublicController.headRoot);
router.get('/favicon.ico', PublicController.favicon);
router.get('/api/verify/init', verifyInitRateLimiter, PublicController.initVerification);
router.post('/api/verify/check', verifyCheckRateLimiter, PublicController.checkVerification);
router.get('/api/analytics/config', PublicController.getAnalyticsConfig);
router.get('/api/inflow/token', PublicController.getInflowToken);
router.post('/api/track/ping', trackPingRateLimiter, PublicController.trackPing);
router.post('/api/track/page-view', postEntryPageViewRateLimiter, PublicController.recordPostEntryPageView);
router.post('/api/track/site-page-view', sitePageViewRateLimiter, PublicController.recordSitePageView);
router.post('/api/inflow/claim', PublicController.deprecatedInflowClaim);
router.get(['/api/config/public', '/api/config'], PublicController.getPublicConfig);
router.get('/api/categories', PublicController.getCategories);
router.get('/api/mirrors', PublicController.getMirrors);
router.get('/api/captcha', captchaRateLimiter, PublicController.getCaptcha);
router.post('/api/links/apply', applyRiskProtection, adaptiveVerificationGate, PublicController.applyLink);
router.get('/api/links', requireReadAccess('links:list'), limitReadConcurrency, PublicController.getLinks);
router.get('/api/showcase', requireReadAccess('showcase:read'), limitReadConcurrency, PublicController.getAds);
router.post('/api/showcase/diagnostics', showcaseDiagnosticRateLimiter, PublicController.recordShowcaseDiagnostics);
router.get('/api/links/:id', requireReadAccess('links:detail'), limitReadConcurrency, PublicController.getLinkDetail);
router.get('/go', outboundRiskProtection, adaptiveVerificationGate, PublicController.go);

module.exports = router;
