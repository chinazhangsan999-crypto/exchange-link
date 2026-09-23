'use strict';

const express = require('express');
const { requireClient, requireClientScope } = require('../middlewares/clientAuth');
const RiskController = require('../controllers/RiskController');
const AdminController = require('../controllers/AdminController');
const MaintenanceController = require('../controllers/MaintenanceController');
const AnalysisController = require('../controllers/AnalysisController');
const { requireAnalysisScope } = require('../middlewares/analysisAuth');
const { requireMaintenanceRead } = require('../middlewares/maintenanceAuth');
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
router.get('/admin/api/analysis/google-drive/oauth/callback', AdminController.googleDriveOAuthCallback);
router.use('/admin/api', requireAdmin);
router.post('/admin/api/logout', requireCsrf, AdminController.logout);
router.get('/admin/api/overview', AdminController.overview);
router.get('/admin/api/sites', AdminController.sites);
router.put('/admin/api/sites/:siteKey/status', requireCsrf, AdminController.setSiteStatus);
router.post('/admin/api/integrations', requireCsrf, AdminController.saveIntegration);
router.put('/admin/api/integrations/:siteKey/controls', requireCsrf, AdminController.setSiteControls);
router.put('/admin/api/clients/:clientId/status', requireCsrf, AdminController.setClientStatus);
router.post('/admin/api/clients/:clientId/rotate', requireCsrf, AdminController.rotateClientSecret);
router.get('/admin/api/risk/summary', AdminController.riskSummary);
router.get('/admin/api/risk/suspects', AdminController.suspects);
router.get('/admin/api/risk/suspects/:siteKey/:visitorHash', AdminController.suspectDetail);
router.post('/admin/api/risk/suspects/:siteKey/:visitorHash/action', requireCsrf, AdminController.setSuspectAction);
router.delete('/admin/api/risk/suspects/:siteKey/:visitorHash/action', requireCsrf, AdminController.clearSuspectAction);
router.get('/admin/api/risk/rules', AdminController.rules);
router.get('/admin/api/risk/rules/revisions', AdminController.ruleRevisions);
router.get('/admin/api/risk/policies', AdminController.policies);
router.post('/admin/api/risk/policies', requireCsrf, AdminController.createPolicy);
router.post('/admin/api/risk/policies/:id/activate', requireCsrf, AdminController.activatePolicy);
router.get('/admin/api/risk/rules/preview', AdminController.previewRule);
router.post('/admin/api/risk/rules', requireCsrf, AdminController.createRule);
router.put('/admin/api/risk/rules/:id/status', requireCsrf, AdminController.setRuleStatus);
router.delete('/admin/api/risk/rules/:id', requireCsrf, AdminController.deleteRule);
router.get('/admin/api/detection/capabilities', AdminController.detectionCapabilities);
router.get('/admin/api/detection/quality', AdminController.detectionQuality);
router.get('/admin/api/detection/pipeline', AdminController.pipelineHealth);
router.get('/admin/api/detection/identity-lists', AdminController.identityEntries);
router.post('/admin/api/detection/identity-lists', requireCsrf, AdminController.saveIdentityEntry);
router.put('/admin/api/detection/identity-lists/:listType/:id', requireCsrf, AdminController.updateIdentityEntry);
router.post('/admin/api/detection/identity-lists/:listType/:id/toggle', requireCsrf, AdminController.toggleIdentityEntry);
router.delete('/admin/api/detection/identity-lists/:listType/:id', requireCsrf, AdminController.deleteIdentityEntry);
router.get('/admin/api/security', AdminController.securityOverview);
router.put('/admin/api/security/credentials', requireCsrf, AdminController.changeCredentials);
router.delete('/admin/api/security/sessions/:id', requireCsrf, AdminController.revokeSession);
router.post('/admin/api/security/sessions/revoke-others', requireCsrf, AdminController.revokeOtherSessions);
router.post('/admin/api/security/sessions/revoke-all', requireCsrf, AdminController.revokeAllSessions);
router.get('/admin/api/audits', AdminController.audits);
router.get('/admin/api/alerts/settings', AdminController.alertSettings);
router.put('/admin/api/alerts/settings', requireCsrf, AdminController.saveAlertSettings);
router.get('/admin/api/alerts/activity', AdminController.alertActivity);
router.post('/admin/api/alerts/test/:provider', requireCsrf, AdminController.testAlert);
router.get('/admin/api/rule-backups/settings', AdminController.ruleBackupSettings);
router.put('/admin/api/rule-backups/settings', requireCsrf, AdminController.saveRuleBackupSettings);
router.get('/admin/api/rule-backups/status', AdminController.ruleBackupStatus);
router.post('/admin/api/rule-backups/test', requireCsrf, AdminController.testRuleBackup);
router.post('/admin/api/rule-backups/run', requireCsrf, AdminController.runRuleBackup);
router.post('/admin/api/rule-backups/retry', requireCsrf, AdminController.retryRuleBackup);
router.get('/admin/api/maintenance/projects', AdminController.maintenanceProjects);
router.get('/admin/api/maintenance/sites', AdminController.maintenanceSites);
router.post('/admin/api/maintenance/check', requireCsrf, AdminController.checkMaintenanceProjects);
router.put('/admin/api/maintenance/projects/:projectKey/status', requireCsrf, AdminController.setMaintenanceProjectStatus);
router.post('/admin/api/maintenance/token', requireCsrf, AdminController.createMaintenanceToken);
router.post('/admin/api/analysis/token', requireCsrf, AdminController.createAnalysisToken);
router.post('/admin/api/analysis/export', requireCsrf, AdminController.exportAnalysis);
router.get('/admin/api/analysis/google-drive', AdminController.googleDriveSettings);
router.put('/admin/api/analysis/google-drive', requireCsrf, AdminController.saveGoogleDriveSettings);
router.post('/admin/api/analysis/google-drive/test', requireCsrf, AdminController.testGoogleDrive);
router.post('/admin/api/analysis/google-drive/backup', requireCsrf, AdminController.backupGoogleDrive);
router.post('/admin/api/analysis/google-drive/connect', requireCsrf, AdminController.connectGoogleDrive);
router.post('/admin/api/analysis/google-drive/disconnect', requireCsrf, AdminController.disconnectGoogleDrive);
router.get('/v1/maintenance/snapshot', requireMaintenanceRead, MaintenanceController.snapshot);
router.get('/v1/maintenance/upstreams', requireMaintenanceRead, MaintenanceController.upstreams);
router.get('/v1/analysis/suspects', requireAnalysisScope('suspects:list'), AnalysisController.suspects);
router.get('/v1/analysis/suspects/:siteKey/:visitorHash', requireAnalysisScope('suspects:detail'), AnalysisController.suspectDetail);
router.use('/v1', requireClient);
router.post('/v1/events/batch', requireClientScope('risk.events.write'), RiskController.events);
router.get('/v1/decisions/delta', requireClientScope('risk.decisions.read'), RiskController.decisions);
router.post('/v1/evaluate', requireClientScope('risk.decisions.read'), RiskController.evaluate);
router.get('/v1/policies/current', requireClientScope('risk.policy.read'), RiskController.policy);
router.post('/v1/agent/inventory', requireClientScope('maintenance.inventory.write'), RiskController.inventory);
router.get('/v1/agent/advisories', requireClientScope('maintenance.advisory.read'), RiskController.advisories);
router.post('/v1/agent/test-results', requireClientScope('maintenance.test-result.write'), RiskController.testResults);

module.exports = router;
