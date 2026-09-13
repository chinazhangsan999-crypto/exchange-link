'use strict';

const crypto = require('crypto');
const { GUEST_JWT_SECRET } = require('../config/env');
const PartnerPageViewModel = require('../models/PartnerPageViewModel');
const { toSqliteUtcTimestamp } = require('../utils/time');

const FLUSH_INTERVAL_MS = 10 * 1000;
const FLUSH_SIZE = 50;
const RETENTION_DAYS = 45;
const visitSecret = crypto.createHmac('sha256', GUEST_JWT_SECRET).update('partner-page-view-v1').digest();

let buffer = [];
let flushTimer = null;
let flushPromise = null;
let accepting = true;

function hashVisit(visitId) {
  return crypto.createHmac('sha256', visitSecret).update(String(visitId || '')).digest('hex');
}

function record({ partnerId, visitId, pageKind, occurredAt = new Date() }) {
  if (!accepting || !Number.isSafeInteger(Number(partnerId)) || !visitId || !['entry', 'page'].includes(pageKind)) return false;
  const date = occurredAt instanceof Date ? occurredAt : new Date(occurredAt);
  if (Number.isNaN(date.getTime())) return false;
  buffer.push({ partnerId: Number(partnerId), visitHash: hashVisit(visitId), pageKind, createdAt: toSqliteUtcTimestamp(date) });
  if (buffer.length >= FLUSH_SIZE) scheduleFlush();
  return true;
}

function recordConfirmedEntry(input) { return record({ ...input, pageKind: 'entry' }); }
function recordPageView(input) { return record({ ...input, pageKind: 'page' }); }

async function flush() {
  if (flushPromise) return flushPromise;
  if (!buffer.length) return { rows: 0 };
  const pending = buffer;
  buffer = [];
  flushPromise = PartnerPageViewModel.insertBatch(pending)
    .catch(error => { buffer.unshift(...pending); throw error; })
    .finally(() => { flushPromise = null; });
  return flushPromise;
}

function scheduleFlush() {
  void flush().catch(error => console.warn('[入站后站内浏览统计] 批量写入失败，将在下次重试：', error.message));
}

function start() {
  if (flushTimer) return;
  accepting = true;
  flushTimer = setInterval(scheduleFlush, FLUSH_INTERVAL_MS);
  flushTimer.unref();
}

async function stopAndFlush() {
  accepting = false;
  if (flushTimer) clearInterval(flushTimer);
  flushTimer = null;
  if (flushPromise) await flushPromise;
  if (buffer.length) await flush();
}

function cleanupOldData(now = new Date()) {
  const cutoff = toSqliteUtcTimestamp(new Date(now.getTime() - RETENTION_DAYS * 24 * 60 * 60 * 1000));
  return PartnerPageViewModel.cleanupOlderThan(cutoff);
}

module.exports = { start, stopAndFlush, flush, recordConfirmedEntry, recordPageView, cleanupOldData, hashVisit };
