'use strict';

const express = require('express');
const AdminController = require('../controllers/AdminController');
const { requireAdmin } = require('../middlewares/auth');
const { createRateLimiter } = require('../middlewares/rateLimit');
const { siteLogoUpload } = require('../middlewares/siteLogoUpload');

const router = express.Router();
const loginRateLimiter = createRateLimiter('admin-login', 15 * 60 * 1000, 5);

router.post('/api/admin/login', loginRateLimiter, AdminController.login);
router.put('/api/admin/password', requireAdmin, AdminController.changePassword);

// 登录接口之外的所有后台 API 统一在此处鉴权。
router.use('/api/admin', requireAdmin);
router.get('/api/admin/analytics/config', AdminController.getAnalyticsConfig);
router.post('/api/admin/analytics/config', AdminController.saveAnalyticsConfig);
router.get(['/api/admin/config', '/api/admin/settings'], AdminController.getSettings);
router.get('/api/admin/settings/risk-control', AdminController.getRiskControlSettings);
router.post(['/api/admin/config', '/api/admin/settings'], AdminController.saveSettings);
router.post('/api/admin/settings/logo', siteLogoUpload, AdminController.uploadSiteLogo);
router.post('/api/admin/settings/test-webhook', AdminController.testWebhook);
router.post('/api/admin/settings/test-bark', AdminController.testBark);
router.get('/api/admin/webhook/health', AdminController.getWebhookHealth);
router.get('/api/admin/webhook/deliveries', AdminController.listWebhookDeliveries);
router.get('/api/admin/review', AdminController.getReview);
router.get('/api/admin/overview', AdminController.getOverview);
router.get('/api/admin/dashboard/stats', AdminController.getDashboardStats);
router.get('/api/admin/partners', AdminController.getPartners);
router.get('/api/admin/partners/:id/analytics', AdminController.getPartnerAnalytics);
router.post('/api/admin/partners', AdminController.createPartner);
router.put('/api/admin/partners/:id', AdminController.updatePartner);
router.patch('/api/admin/partners/:id', AdminController.updatePartnerApproval);
router.post('/api/admin/partners/:id/whitelist', AdminController.whitelistPartner);
router.post('/api/admin/partners/:id/traffic/clear', AdminController.clearPartnerTraffic);
router.delete('/api/admin/partners/:id', AdminController.deletePartner);
router.post('/api/admin/partners/:id/source-sid/regenerate', AdminController.regeneratePartnerSourceSid);
router.post('/api/admin/links/check-all', AdminController.checkAllLinks);
router.post('/api/admin/links/:id/check', AdminController.checkLink);
router.post('/api/admin/links/:id/ping', AdminController.checkLinkHealth);
router.post('/api/admin/links/:id/reset-lost-count', AdminController.resetLostCount);
router.post('/api/admin/partners/:id/reset-check', AdminController.resetCheckStatus);
router.get('/api/admin/logs', AdminController.getLogs);
router.get('/api/admin/categories', AdminController.getCategories);
router.post('/api/admin/categories', AdminController.createCategory);
router.put('/api/admin/categories/order', AdminController.saveCategoryOrder);
router.delete('/api/admin/categories/:id', AdminController.deleteCategory);
router.get('/api/admin/ads', AdminController.getAds);
router.post('/api/admin/ads', AdminController.createAd);
router.put('/api/admin/ads/:id', AdminController.updateAd);
router.patch('/api/admin/ads/:id/status', AdminController.updateAdStatus);
router.delete('/api/admin/ads/:id', AdminController.deleteAd);
router.get('/api/admin/mirrors', AdminController.getMirrors);
router.post('/api/admin/mirrors', AdminController.createMirror);
router.put('/api/admin/mirrors/:url', AdminController.updateMirror);
router.patch('/api/admin/mirrors/:url/status', AdminController.updateMirrorStatus);
router.delete('/api/admin/mirrors/:url', AdminController.deleteMirror);
router.post('/api/admin/sync/partners', AdminController.syncPartnersMatrix);
router.post('/api/admin/sync/ads', AdminController.syncAdsMatrix);
router.post('/api/admin/sync/mirrors', AdminController.syncMirrorsMatrix);
router.get('/api/admin/export/:type', AdminController.exportMatrix);

// 所有后台 HTML 入口统一经过带 nonce 的严格 CSP 响应；页面内 API 仍由上述中间件保护。
router.get(['/admin/ads', '/admin/ads/add', '/admin/ads/edit/:id'], (req, res) => res.redirect(302, '/admin#ads'));
// 兼容传统表单命名；当前单页后台实际通过同一 Controller 的 JSON API 调用。
router.post('/admin/ads/add', requireAdmin, AdminController.createAd);
router.post('/admin/ads/edit/:id', requireAdmin, AdminController.updateAd);
router.post('/admin/ads/delete/:id', requireAdmin, AdminController.deleteAd);
router.get('/admin/mirrors', (req, res) => res.redirect(302, '/admin#mirrors'));
router.get(['/admin', '/admin/', '/admin/index.html'], AdminController.renderAdminPage);

module.exports = router;
