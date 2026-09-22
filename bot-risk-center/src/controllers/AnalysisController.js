'use strict';

const AnalysisService = require('../services/AnalysisService');

function queryInput(req) {
  return {
    siteKey: String(req.query.siteKey || ''),
    minScore: req.query.minScore,
    since: String(req.query.since || ''),
    page: req.query.page,
    limit: req.query.limit
  };
}

async function suspects(req, res) {
  return res.json({ code: 200, data: await AnalysisService.list(queryInput(req), req.analysisAccess) });
}

async function suspectDetail(req, res) {
  const siteKey = String(req.params.siteKey || '');
  const visitorHash = String(req.params.visitorHash || '').toLowerCase();
  if (!/^[A-Za-z0-9_-]{3,64}$/.test(siteKey) || !/^[a-f0-9]{32,128}$/.test(visitorHash)) {
    return res.status(400).json({ code: 400, message: '参数无效' });
  }
  const data = await AnalysisService.detail(siteKey, visitorHash, req.analysisAccess);
  if (!data) return res.status(404).json({ code: 404, message: '记录不存在或令牌无权读取' });
  return res.json({ code: 200, data });
}

module.exports = { suspects, suspectDetail };
