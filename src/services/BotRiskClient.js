'use strict';

const crypto = require('crypto');
const {
  BOT_GATE_MODE,
  BOT_RISK_CENTER_ENABLED,
  BOT_RISK_CENTER_URL,
  BOT_RISK_CLIENT_ID,
  BOT_RISK_CLIENT_SECRET,
  BOT_RISK_SITE_KEY,
  BOT_RISK_TIMEOUT_MS,
  BOT_RISK_SYNC_INTERVAL_MS
} = require('../config/env');
const LocalRiskDecisionCache = require('./LocalRiskDecisionCache');

const MAX_QUEUE_SIZE = 10000;
const BATCH_SIZE = 100;
let queue = [];
let flushTimer = null;
let decisionTimer = null;
let flushing = false;
let syncing = false;
let stopped = true;

function enabled() {
  return BOT_RISK_CENTER_ENABLED && BOT_GATE_MODE !== 'off';
}

function subjectHash(visitorId) {
  return crypto.createHmac('sha256', BOT_RISK_CLIENT_SECRET || 'local-disabled-risk-client')
    .update(String(visitorId || ''))
    .digest('hex');
}

function canonical(method, pathAndQuery, timestamp, nonce, rawBody) {
  return [
    method.toUpperCase(),
    pathAndQuery,
    timestamp,
    nonce,
    crypto.createHash('sha256').update(rawBody).digest('hex')
  ].join('\n');
}

async function signedRequest(method, pathAndQuery, body) {
  const rawBody = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(18).toString('base64url');
  const signature = crypto.createHmac('sha256', BOT_RISK_CLIENT_SECRET)
    .update(canonical(method, pathAndQuery, timestamp, nonce, rawBody))
    .digest('hex');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), BOT_RISK_TIMEOUT_MS);
  try {
    const response = await fetch(`${BOT_RISK_CENTER_URL}${pathAndQuery}`, {
      method,
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        ...(rawBody.length ? { 'Content-Type': 'application/json' } : {}),
        'X-Risk-Client': BOT_RISK_CLIENT_ID,
        'X-Risk-Site': BOT_RISK_SITE_KEY,
        'X-Risk-Timestamp': timestamp,
        'X-Risk-Nonce': nonce,
        'X-Risk-Signature': signature
      },
      body: rawBody.length ? rawBody : undefined
    });
    if (!response.ok) throw new Error(`risk center returned ${response.status}`);
    return response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function enqueue(visitorId, eventType, evidence = {}) {
  if (!enabled() || !visitorId) return false;
  const event = {
    eventId: crypto.randomUUID(),
    visitorHash: subjectHash(visitorId),
    eventType: String(eventType || '').slice(0, 64),
    occurredAt: Date.now(),
    evidence: evidence && typeof evidence === 'object' ? evidence : {}
  };
  if (!/^[a-z0-9_-]{2,64}$/i.test(event.eventType)) return false;
  if (queue.length >= MAX_QUEUE_SIZE) queue.shift();
  queue.push(event);
  if (queue.length >= BATCH_SIZE) void flush();
  return true;
}

async function flush() {
  if (!enabled() || flushing || !queue.length) return { sent: 0 };
  flushing = true;
  const batch = queue.splice(0, BATCH_SIZE);
  try {
    await signedRequest('POST', '/v1/events/batch', { events: batch });
    return { sent: batch.length };
  } catch (error) {
    queue = [...batch, ...queue].slice(0, MAX_QUEUE_SIZE);
    return { sent: 0, error: error.name === 'AbortError' ? 'timeout' : error.message };
  } finally {
    flushing = false;
  }
}

async function syncDecisions() {
  if (!enabled() || syncing) return { applied: 0 };
  syncing = true;
  try {
    const cursor = LocalRiskDecisionCache.getCursor();
    const result = await signedRequest('GET', `/v1/decisions/delta?cursor=${cursor}&limit=1000`);
    return { applied: LocalRiskDecisionCache.setMany(result?.data?.items || []) };
  } catch (error) {
    return { applied: 0, error: error.name === 'AbortError' ? 'timeout' : error.message };
  } finally {
    syncing = false;
  }
}

function getDecision(visitorId) {
  if (!enabled() || !visitorId) return null;
  const hash = subjectHash(visitorId);
  const decision = LocalRiskDecisionCache.get(hash);
  if (!decision) return null;
  return { ...decision, subjectHash: hash, enforce: BOT_GATE_MODE === 'enforce' };
}

function markChallengePassed(visitorId) {
  if (!visitorId) return;
  const hash = subjectHash(visitorId);
  LocalRiskDecisionCache.markChallengePassed(hash);
  enqueue(visitorId, 'challenge_passed');
}

function hasChallengeBypass(visitorId) {
  return visitorId ? LocalRiskDecisionCache.hasChallengeBypass(subjectHash(visitorId)) : false;
}

function start() {
  if (!enabled() || !stopped) return;
  stopped = false;
  flushTimer = setInterval(() => { void flush(); }, 1000);
  decisionTimer = setInterval(() => { void syncDecisions(); }, BOT_RISK_SYNC_INTERVAL_MS);
  flushTimer.unref?.();
  decisionTimer.unref?.();
  void syncDecisions();
}

async function stop() {
  stopped = true;
  if (flushTimer) clearInterval(flushTimer);
  if (decisionTimer) clearInterval(decisionTimer);
  flushTimer = null;
  decisionTimer = null;
  return flush();
}

function status() {
  return { enabled: enabled(), mode: BOT_GATE_MODE, queued: queue.length, cursor: LocalRiskDecisionCache.getCursor() };
}

module.exports = {
  subjectHash,
  enqueue,
  flush,
  syncDecisions,
  getDecision,
  markChallengePassed,
  hasChallengeBypass,
  start,
  stop,
  status
};
