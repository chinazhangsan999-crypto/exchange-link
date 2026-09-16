'use strict';

const express = require('express');
const SetupController = require('../controllers/SetupController');
const { createRateLimiter } = require('../middlewares/rateLimit');

const router = express.Router();
const setupRateLimiter = createRateLimiter('cloudflare-bootstrap', 60 * 60 * 1000, 5);

router.get('/setup', SetupController.renderSetup);
router.get('/setup/client.js', SetupController.renderSetupClient);
router.get('/api/setup/status', SetupController.getStatus);
router.post('/api/setup/deploy', setupRateLimiter, SetupController.deploy);

module.exports = router;
