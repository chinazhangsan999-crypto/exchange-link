'use strict';

const express = require('express');
const { requireClient } = require('../middlewares/clientAuth');
const RiskController = require('../controllers/RiskController');
const AdminController = require('../controllers/AdminController');
const { requireAdmin, requireCsrf } = require('../services/AdminAuthService');
const StorageService = require('../services/StorageService');

const router = express.Router();
router.get('/health', (req, res) => res.json({ ok: true }));
router.get('/ready', (req, res) => StorageService.isReady()
  ? res.json({ ready: true })
  : res.status(503).json({ ready: false }));
router.use('/admin', (req, res, next) => {
  res.set({
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
  });
  next();
});
router.get(['/admin', '/admin/'], AdminController.page);
router.get('/admin/assets/admin.css', AdminController.stylesheet);
router.get('/admin/assets/admin.js', AdminController.script);
router.post('/admin/api/login', AdminController.login);
router.get('/admin/api/session', AdminController.session);
router.use('/admin/api', requireAdmin);
router.post('/admin/api/logout', requireCsrf, AdminController.logout);
router.get('/admin/api/overview', AdminController.overview);
router.get('/admin/api/sites', AdminController.sites);
router.put('/admin/api/sites/:siteKey/status', requireCsrf, AdminController.setSiteStatus);
router.use('/v1', requireClient);
router.post('/v1/events/batch', RiskController.events);
router.get('/v1/decisions/delta', RiskController.decisions);
router.post('/v1/evaluate', RiskController.evaluate);
router.get('/v1/policies/current', RiskController.policy);

module.exports = router;
