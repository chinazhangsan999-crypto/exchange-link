'use strict';

const crypto = require('crypto');
const { GUEST_JWT_SECRET } = require('../config/env');
const SiteTrafficModel = require('../models/SiteTrafficModel');
const { getLocalDayUtcRange, toSqliteUtcTimestamp } = require('../utils/time');

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const SHANGHAI_OFFSET_MS = 8 * HOUR_MS;
const FLUSH_INTERVAL_MS = 30 * 1000;
const FLUSH_SIZE = 100;
const CACHE_TTL_MS = 60 * 1000;
const RETENTION_DAYS = 45;
const ipHmacSecret = crypto.createHmac('sha256', GUEST_JWT_SECRET).update('site-traffic-ip-v1').digest();

let buffer = new Map();
let flushPromise = null;
let flushTimer = null;
let accepting = true;
let latestBucket = '';
const queryCache = new Map();

const floorUtcHour = milliseconds => Math.floor(milliseconds / HOUR_MS) * HOUR_MS;
const floorShanghaiDay = milliseconds => Math.floor((milliseconds + SHANGHAI_OFFSET_MS) / DAY_MS) * DAY_MS - SHANGHAI_OFFSET_MS;
const floorShanghaiThreeHours = milliseconds => Math.floor((milliseconds + SHANGHAI_OFFSET_MS) / (3 * HOUR_MS)) * 3 * HOUR_MS - SHANGHAI_OFFSET_MS;
const toShanghaiIso = milliseconds => `${new Date(milliseconds + SHANGHAI_OFFSET_MS).toISOString().slice(0, 19)}+08:00`;
const safeCount = value => Math.max(0, Number(value) || 0);

function invalidateCache() {
  queryCache.clear();
}

function cached(key, loader) {
  const now = Date.now();
  const existing = queryCache.get(key);
  if (existing && existing.expiresAt > now) return existing.promise;
  const promise = Promise.resolve().then(loader).catch(error => {
    if (queryCache.get(key)?.promise === promise) queryCache.delete(key);
    throw error;
  });
  queryCache.set(key, { expiresAt: now + CACHE_TTL_MS, promise });
  return promise;
}

function hashIp(normalizedIp) {
  return crypto.createHmac('sha256', ipHmacSecret).update(String(normalizedIp || '')).digest('hex');
}

function hashVisitor(visitorId) {
  return crypto.createHash('sha256').update(String(visitorId || '')).digest('hex');
}

function mergeBack(items) {
  for (const item of items) {
    const key = `${item.bucketStart}\u0000${item.visitorHash}\u0000${item.ipHash}`;
    const current = buffer.get(key);
    if (!current) buffer.set(key, item);
    else {
      current.pvCount += item.pvCount;
      if (item.firstSeenAt < current.firstSeenAt) current.firstSeenAt = item.firstSeenAt;
      if (item.lastSeenAt > current.lastSeenAt) current.lastSeenAt = item.lastSeenAt;
    }
  }
}

async function flush() {
  if (flushPromise) return flushPromise;
  if (buffer.size === 0) return { rows: 0, pv: 0 };
  const pending = [...buffer.values()];
  buffer = new Map();
  flushPromise = SiteTrafficModel.upsertHourlyBatch(pending)
    .then(result => { invalidateCache(); return result; })
    .catch(error => { mergeBack(pending); throw error; })
    .finally(() => { flushPromise = null; });
  return flushPromise;
}

function scheduleFlush() {
  void flush().catch(error => console.warn('[全站访客统计] 批量写入失败，将在下次重试：', error.message));
}

function recordPageView({ visitorId, normalizedIp, occurredAt = new Date() }) {
  if (!accepting || !visitorId || !normalizedIp) return false;
  const now = occurredAt instanceof Date ? occurredAt : new Date(occurredAt);
  if (Number.isNaN(now.getTime())) return false;
  const bucketStart = toSqliteUtcTimestamp(new Date(floorUtcHour(now.getTime())));
  const timestamp = toSqliteUtcTimestamp(now);
  const visitorHash = hashVisitor(visitorId);
  const ipHash = hashIp(normalizedIp);
  const key = `${bucketStart}\u0000${visitorHash}\u0000${ipHash}`;
  const current = buffer.get(key);
  if (current) {
    current.pvCount += 1;
    current.lastSeenAt = timestamp;
  } else {
    buffer.set(key, { bucketStart, visitorHash, ipHash, pvCount: 1, firstSeenAt: timestamp, lastSeenAt: timestamp });
  }
  if (latestBucket && latestBucket !== bucketStart) scheduleFlush();
  latestBucket = bucketStart;
  if (buffer.size >= FLUSH_SIZE) scheduleFlush();
  return true;
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
  if (buffer.size) await flush();
}

async function getTodaySummary(now = new Date()) {
  const range = getLocalDayUtcRange(now);
  const cacheKey = `today:${range.start}`;
  return cached(cacheKey, async () => {
    const row = await SiteTrafficModel.getSummaryBetween(range.start, range.end);
    return { total_ip: safeCount(row?.total_ip), total_uv: safeCount(row?.total_uv), total_pv: safeCount(row?.total_pv) };
  });
}

async function get24HourTrend(now) {
  const currentHour = floorUtcHour(now.getTime());
  const points = Array.from({ length: 25 }, (_, index) => currentHour - (24 - index) * HOUR_MS);
  const rows = await SiteTrafficModel.getHourlyBetween(
    toSqliteUtcTimestamp(new Date(points[0])),
    toSqliteUtcTimestamp(new Date(currentHour + HOUR_MS))
  );
  const lookup = new Map(rows.map(row => [row.bucket_start, row]));
  return points.map(point => {
    const row = lookup.get(toSqliteUtcTimestamp(new Date(point))) || {};
    return {
      time: toShanghaiIso(point), windowStart: toShanghaiIso(point), windowEnd: toShanghaiIso(point + HOUR_MS),
      total_ip: safeCount(row.total_ip), total_uv: safeCount(row.total_uv), total_pv: safeCount(row.total_pv)
    };
  });
}

async function get7DayTrend(now) {
  const end = floorShanghaiThreeHours(now.getTime());
  const samples = Array.from({ length: 56 }, (_, index) => {
    const point = end - (55 - index) * 3 * HOUR_MS;
    return { point, start: point - DAY_MS, end: toSqliteUtcTimestamp(new Date(point)) };
  });
  const rows = await SiteTrafficModel.getRolling24HourSamples(samples);
  const lookup = new Map(rows.map(row => [Number(row.sample_index), row]));
  return samples.map((sample, index) => {
    const row = lookup.get(index) || {};
    return {
      time: toShanghaiIso(sample.point), windowStart: toShanghaiIso(sample.start), windowEnd: toShanghaiIso(sample.point),
      total_ip: safeCount(row.total_ip), total_uv: safeCount(row.total_uv), total_pv: safeCount(row.total_pv)
    };
  });
}

async function get30DayTrend(now) {
  const todayStart = floorShanghaiDay(now.getTime());
  const starts = Array.from({ length: 30 }, (_, index) => todayStart - (29 - index) * DAY_MS);
  const end = todayStart + DAY_MS;
  const rows = await SiteTrafficModel.getDailyBetween(
    toSqliteUtcTimestamp(new Date(starts[0])),
    toSqliteUtcTimestamp(new Date(end))
  );
  const lookup = new Map(rows.map(row => [row.local_day, row]));
  return starts.map(start => {
    const day = new Date(start + SHANGHAI_OFFSET_MS).toISOString().slice(0, 10);
    const row = lookup.get(day) || {};
    return {
      time: `${day}T00:00:00+08:00`, windowStart: `${day}T00:00:00+08:00`,
      windowEnd: start === todayStart ? toShanghaiIso(now.getTime()) : toShanghaiIso(start + DAY_MS),
      total_ip: safeCount(row.total_ip), total_uv: safeCount(row.total_uv), total_pv: safeCount(row.total_pv)
    };
  });
}

async function getTrend(inputRange, now = new Date()) {
  const range = ['24h', '7d', '30d'].includes(inputRange) ? inputRange : '7d';
  const bucket = range === '24h' ? floorUtcHour(now.getTime())
    : range === '7d' ? floorShanghaiThreeHours(now.getTime()) : floorShanghaiDay(now.getTime());
  return cached(`trend:${range}:${bucket}`, async () => {
    const series = range === '24h' ? await get24HourTrend(now)
      : range === '30d' ? await get30DayTrend(now) : await get7DayTrend(now);
    return {
      range,
      timezone: 'Asia/Shanghai',
      granularity: range === '24h' ? '1h' : range === '7d' ? '3h' : '1d',
      metricMode: range === '7d' ? 'rolling_24h' : 'period_total',
      series
    };
  });
}

async function cleanupOldData(now = new Date()) {
  const cutoff = toSqliteUtcTimestamp(new Date(floorUtcHour(now.getTime() - RETENTION_DAYS * DAY_MS)));
  const result = await SiteTrafficModel.cleanupOlderThan(cutoff);
  invalidateCache();
  return result;
}

function getBufferStats() {
  return { entries: buffer.size, flushing: Boolean(flushPromise), accepting };
}

module.exports = { start, stopAndFlush, recordPageView, flush, getTodaySummary, getTrend, cleanupOldData, getBufferStats };
