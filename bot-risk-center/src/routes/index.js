'use strict';

const express = require('express');
const { requireClient } = require('../middlewares/clientAuth');
const RiskController = require('../controllers/RiskController');
const StorageService = require('../services/StorageService');

const router = express.Router();
router.get('/health', (req, res) => res.json({ ok: true }));
router.get('/ready', (req, res) => StorageService.isReady()
  ? res.json({ ready: true })
  : res.status(503).json({ ready: false }));
router.use('/v1', requireClient);
router.post('/v1/events/batch', RiskController.events);
router.get('/v1/decisions/delta', RiskController.decisions);
router.post('/v1/evaluate', RiskController.evaluate);
router.get('/v1/policies/current', RiskController.policy);

module.exports = router;
