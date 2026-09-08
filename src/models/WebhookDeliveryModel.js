'use strict';

const { run, all, get } = require('../config/database');

const MAX_REASON_LENGTH = 300;

function cleanReason(value) {
  return String(value || '').replace(/https?:\/\/[^\s]+/gi, '[已隐藏地址]').slice(0, MAX_REASON_LENGTH);
}

async function recordDelivery({
  eventType = 'system', provider = 'config', isFallback = false, success = false,
  attemptCount = 0, statusCode = null, errorCode = null, errorMessage = null, durationMs = null
}) {
  const normalizedStatusCode = statusCode === null || statusCode === undefined || statusCode === ''
    ? null : (Number.isInteger(Number(statusCode)) ? Number(statusCode) : null);
  return run(`INSERT INTO webhook_delivery_logs(
    event_type, provider, is_fallback, success, attempt_count, status_code,
    error_code, error_message, duration_ms
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
    String(eventType).slice(0, 80),
    String(provider).slice(0, 30),
    isFallback ? 1 : 0,
    success ? 1 : 0,
    Math.max(0, Number(attemptCount) || 0),
    normalizedStatusCode,
    errorCode ? String(errorCode).slice(0, 80) : null,
    errorMessage ? cleanReason(errorMessage) : null,
    Number.isFinite(Number(durationMs)) ? Math.max(0, Math.round(Number(durationMs))) : null
  ], { priority: 'background', label: 'record webhook delivery' });
}

async function listDeliveries(limit = 50) {
  const safeLimit = Math.min(100, Math.max(1, Number.parseInt(limit, 10) || 50));
  return all(`SELECT id, event_type, provider, is_fallback, success, attempt_count,
    status_code, error_code, error_message, duration_ms, created_at
    FROM webhook_delivery_logs ORDER BY id DESC LIMIT ?`, [safeLimit]);
}

async function providerSummary(provider) {
  if (!provider) return { records: [], success24h: 0, failed24h: 0, successRate24h: 0, consecutiveFailures: 0 };
  const [recent, totals] = await Promise.all([
    all(`SELECT success, status_code, error_code, error_message, created_at
      FROM webhook_delivery_logs WHERE provider = ? ORDER BY id DESC LIMIT 100`, [provider]),
    get(`SELECT
      SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS success_count,
      SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed_count
      FROM webhook_delivery_logs
      WHERE provider = ? AND created_at >= datetime('now', '-24 hours')`, [provider])
  ]);
  let consecutiveFailures = 0;
  for (const row of recent) {
    if (Number(row.success) === 1) break;
    consecutiveFailures += 1;
  }
  const success24h = Number(totals?.success_count || 0);
  const failed24h = Number(totals?.failed_count || 0);
  const lastSuccess = recent.find(row => Number(row.success) === 1) || null;
  const lastFailure = recent.find(row => Number(row.success) === 0) || null;
  return {
    records: recent,
    success24h,
    failed24h,
    successRate24h: success24h + failed24h ? Number((success24h * 100 / (success24h + failed24h)).toFixed(1)) : 0,
    consecutiveFailures,
    lastSuccessAt: lastSuccess?.created_at || null,
    lastFailureAt: lastFailure?.created_at || null,
    lastFailureReason: lastFailure ? (lastFailure.error_message || (lastFailure.status_code ? `HTTP ${lastFailure.status_code}` : '未知错误')) : null,
    lastFailureStatusCode: lastFailure?.status_code || null
  };
}

async function getHealth(primaryProvider) {
  const [primary, bark, lastFallback] = await Promise.all([
    providerSummary(primaryProvider),
    providerSummary('bark'),
    get(`SELECT created_at FROM webhook_delivery_logs
      WHERE is_fallback = 1 AND success = 1 ORDER BY id DESC LIMIT 1`)
  ]);
  return { primary, bark, lastFallbackAt: lastFallback?.created_at || null };
}

module.exports = { recordDelivery, listDeliveries, providerSummary, getHealth };
