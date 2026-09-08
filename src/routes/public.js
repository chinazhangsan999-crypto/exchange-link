'use strict';

const express = require('express');
const PublicController = require('../controllers/PublicController');
const { createRateLimiter } = require('../middlewares/rateLimit');

const router = express.Router();
const applyRateLimiter = createRateLimiter('link-apply', 5 * 60 * 1000, 5);
const captchaRateLimiter = createRateLimiter('captcha', 60 * 60 * 1000, 20);
const trafficRateLimiter = createRateLimiter('traffic', 10 * 1000, 30);
const verifyInitRateLimiter = createRateLimiter('verify-init', 10 * 60 * 1000, 20);
const verifyCheckRateLimiter = createRateLimiter('verify-check', 10 * 60 * 1000, 10);
const showcaseDiagnosticRateLimiter = createRateLimiter('showcase-diagnostics', 60 * 1000, 20);

router.get('/api/health', PublicController.health);
router.head('/', PublicController.headRoot);
router.get('/favicon.ico', PublicController.favicon);
router.get('/api/verify/init', verifyInitRateLimiter, PublicController.initVerification);
router.post('/api/verify/check', verifyCheckRateLimiter, PublicController.checkVerification);
router.get('/api/analytics/config', PublicController.getAnalyticsConfig);
router.get('/api/inflow/token', PublicController.getInflowToken);
router.post('/api/track/ping', trafficRateLimiter, PublicController.trackPing);
router.post('/api/inflow/claim', PublicController.deprecatedInflowClaim);
router.get(['/api/config/public', '/api/config'], PublicController.getPublicConfig);
router.get('/api/categories', PublicController.getCategories);
router.get('/api/mirrors', PublicController.getMirrors);
router.get('/api/captcha', captchaRateLimiter, PublicController.getCaptcha);
router.post('/api/links/apply', applyRateLimiter, PublicController.applyLink);
router.get('/api/links', PublicController.getLinks);
router.get('/api/showcase', PublicController.getAds);
router.post('/api/showcase/diagnostics', showcaseDiagnosticRateLimiter, PublicController.recordShowcaseDiagnostics);
router.get('/api/links/:id', PublicController.getLinkDetail);
router.get('/go', trafficRateLimiter, PublicController.go);

module.exports = router;
