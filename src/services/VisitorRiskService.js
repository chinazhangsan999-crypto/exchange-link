'use strict';

const { LRUCache } = require('lru-cache');

const VISITOR_RISK_TTL_MS = 24 * 60 * 60 * 1000;
const REPEAT_TRAP_WINDOW_MS = 60 * 1000;
const READ_RESTRICTION_MS = 30 * 1000;
const READ_RESTRICTION_SCORE = 80;
const DETAIL_SCAN_WINDOW_MS = 20 * 1000;
const DETAIL_SCAN_DISTINCT_LIMIT = 8;
const DETAIL_SCAN_SEQUENCE_LIMIT = 6;
const DETAIL_MINUTE_WINDOW_MS = 60 * 1000;
const DETAIL_MINUTE_LIMIT = 30;
const SCRIPT_USER_AGENT = /(?:python-requests|curl\/|wget\/|scrapy|go-http-client|aiohttp|httpx\/)/i;

const visitorRiskCache = new LRUCache({
  max: 100000,
  ttl: VISITOR_RISK_TTL_MS
});

function saveRecord(key, record) {
  visitorRiskCache.set(key, record, { ttl: VISITOR_RISK_TTL_MS });
  return record;
}

function addRiskScore(record, points, now) {
  const score = Math.min(100, Number(record.score || 0) + Number(points || 0));
  return {
    ...record,
    score,
    restrictedUntil: score >= READ_RESTRICTION_SCORE
      ? Math.max(Number(record.restrictedUntil || 0), now + READ_RESTRICTION_MS)
      : Number(record.restrictedUntil || 0)
  };
}

function isSameOrigin(value, expectedOrigin) {
  if (!value || !expectedOrigin) return true;
  try { return new URL(value).origin === expectedOrigin; }
  catch { return false; }
}

/**
 * Fetch Metadata 只作为一次性弱信号；缺失本身不会限制读取，避免误伤旧浏览器和 WebView。
 */
function recordBootstrapSignals(visitorId, metadata = {}, now = Date.now()) {
  const key = String(visitorId || '');
  if (!key) return null;
  let record = visitorRiskCache.get(key) || { score: 0, restrictedUntil: 0 };
  const flags = new Set(Array.isArray(record.signalFlags) ? record.signalFlags : []);
  let points = 0;
  const fetchSite = String(metadata.fetchSite || '').toLowerCase();
  const fetchMode = String(metadata.fetchMode || '').toLowerCase();
  const fetchDest = String(metadata.fetchDest || '').toLowerCase();
  const userAgent = String(metadata.userAgent || '');

  if (!fetchSite && !fetchMode && !fetchDest && !flags.has('missing-fetch-metadata')) {
    flags.add('missing-fetch-metadata');
    points += 15;
  }
  if (fetchSite && !['same-origin', 'same-site', 'none'].includes(fetchSite)
    && !flags.has('cross-site-bootstrap')) {
    flags.add('cross-site-bootstrap');
    points += 40;
  }
  if (!isSameOrigin(metadata.origin, metadata.expectedOrigin) && !flags.has('foreign-origin')) {
    flags.add('foreign-origin');
    points += 40;
  }
  if (!isSameOrigin(metadata.referer, metadata.expectedOrigin) && !flags.has('foreign-referer')) {
    flags.add('foreign-referer');
    points += 30;
  }
  if (SCRIPT_USER_AGENT.test(userAgent) && !flags.has('script-user-agent')) {
    flags.add('script-user-agent');
    points += 50;
  }

  record = addRiskScore({ ...record, signalFlags: [...flags] }, points, now);
  return saveRecord(key, record);
}

/** 短时间读取大量不同详情 ID 是强遍历信号；按访客而非共享公网 IP 处理。 */
function recordDetailRead(visitorId, detailId, now = Date.now()) {
  const key = String(visitorId || '');
  const id = Number(detailId);
  if (!key || !Number.isSafeInteger(id) || id <= 0) return null;
  let record = visitorRiskCache.get(key) || { score: 0, restrictedUntil: 0 };
  const recentMinuteReads = (Array.isArray(record.recentDetailReads) ? record.recentDetailReads : [])
    .filter(item => now - Number(item.at || 0) <= DETAIL_MINUTE_WINDOW_MS);
  const recentDetailReads = recentMinuteReads
    .filter(item => now - Number(item.at || 0) <= DETAIL_SCAN_WINDOW_MS);
  recentDetailReads.push({ id, at: now });
  const distinctCount = new Set(recentDetailReads.map(item => item.id)).size;
  const sequence = recentDetailReads.slice(-DETAIL_SCAN_SEQUENCE_LIMIT).map(item => item.id);
  const sequential = sequence.length >= DETAIL_SCAN_SEQUENCE_LIMIT
    && sequence.every((value, index) => index === 0 || value === sequence[index - 1] + 1);
  const minuteCount = recentMinuteReads.length + 1;
  const lastTriggeredAt = Number(record.detailScanTriggeredAt || 0);
  if ((distinctCount >= DETAIL_SCAN_DISTINCT_LIMIT || sequential || minuteCount > DETAIL_MINUTE_LIMIT)
    && now - lastTriggeredAt > DETAIL_SCAN_WINDOW_MS) {
    record = addRiskScore({ ...record, detailScanTriggeredAt: now }, 80, now);
  }
  record.recentDetailReads = [...recentMinuteReads, { id, at: now }].slice(-DETAIL_MINUTE_LIMIT - 1);
  return saveRecord(key, record);
}

function markReadProofVerified(visitorId, now = Date.now()) {
  const key = String(visitorId || '');
  if (!key) return null;
  const record = visitorRiskCache.get(key) || {};
  return saveRecord(key, {
    ...record,
    score: 0,
    restrictedUntil: 0,
    proofVerifiedAt: now,
    recentDetailReads: []
  });
}

function recordTrapdoor(visitorId, metadata = {}, now = Date.now()) {
  const key = String(visitorId || '');
  if (!key) return null;

  const previous = visitorRiskCache.get(key);
  const repeatedQuickly = Boolean(previous && now - Number(previous.lastTrapAt || 0) <= REPEAT_TRAP_WINDOW_MS);
  const score = Math.min(100, Number(previous?.score || 0) + (repeatedQuickly ? 50 : 30));
  const record = {
    score,
    trapHits: Number(previous?.trapHits || 0) + 1,
    lastTrapAt: now,
    lastUserAgent: String(metadata.userAgent || '').slice(0, 300),
    lastPath: String(metadata.path || '').slice(0, 500),
    restrictedUntil: score >= READ_RESTRICTION_SCORE
      ? Math.max(Number(previous?.restrictedUntil || 0), now + READ_RESTRICTION_MS)
      : Number(previous?.restrictedUntil || 0)
  };
  saveRecord(key, { ...previous, ...record });
  return { ...record, repeatedQuickly };
}

function getReadRestriction(visitorId, now = Date.now()) {
  const record = visitorRiskCache.get(String(visitorId || ''));
  if (!record || Number(record.restrictedUntil || 0) <= now) return null;
  return {
    score: Number(record.score || 0),
    retryAfter: Math.max(1, Math.ceil((Number(record.restrictedUntil) - now) / 1000))
  };
}

module.exports = {
  VISITOR_RISK_TTL_MS,
  REPEAT_TRAP_WINDOW_MS,
  READ_RESTRICTION_MS,
  DETAIL_SCAN_WINDOW_MS,
  DETAIL_SCAN_DISTINCT_LIMIT,
  DETAIL_SCAN_SEQUENCE_LIMIT,
  DETAIL_MINUTE_WINDOW_MS,
  DETAIL_MINUTE_LIMIT,
  recordTrapdoor,
  recordBootstrapSignals,
  recordDetailRead,
  markReadProofVerified,
  getReadRestriction
};
