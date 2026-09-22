'use strict';

const { LRUCache } = require('lru-cache');
const RiskScoringService = require('./RiskScoringService');

const DEFAULT_POLICY_VERSION = 'baseline-1';
const decisions = new LRUCache({ max: 500_000, ttl: 24 * 60 * 60_000 });
const eventIds = new LRUCache({ max: 1_000_000, ttl: 24 * 60 * 60_000 });
let sequence = 0;
const delta = [];

function key(siteKey, visitorHash) {
  return `${siteKey}:${visitorHash}`;
}

function normalizeEvent(input, siteKey) {
  const eventId = String(input?.eventId || '');
  const visitorHash = String(input?.visitorHash || '');
  const eventType = String(input?.eventType || '');
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(eventId)
    || !/^[a-f0-9]{32,128}$/i.test(visitorHash)
    || !/^[a-z0-9_-]{2,64}$/i.test(eventType)) return null;
  return {
    eventId,
    siteKey,
    visitorHash: visitorHash.toLowerCase(),
    eventType,
    occurredAt: Number(input.occurredAt) || Date.now(),
    evidence: input.evidence && typeof input.evidence === 'object' ? input.evidence : {}
  };
}

function applyEvents(siteKey, inputs = [], now = Date.now(), policy = {}) {
  const accepted = [];
  const touched = new Map();
  for (const input of inputs.slice(0, 500)) {
    const event = normalizeEvent(input, siteKey);
    if (!event || eventIds.has(event.eventId)) continue;
    eventIds.set(event.eventId, true);
    accepted.push(event);
    const visitorEvents = touched.get(event.visitorHash) || [];
    visitorEvents.push({ signal: event.eventType });
    touched.set(event.visitorHash, visitorEvents);
  }

  const updated = [];
  for (const [visitorHash, visitorEvents] of touched) {
    const cacheKey = key(siteKey, visitorHash);
    const previous = decisions.get(cacheKey);
    const result = RiskScoringService.evaluate(visitorEvents, previous?.score || 0, policy.configuration || policy);
    const item = {
      sequence: ++sequence,
      siteKey,
      subjectType: 'visitor',
      subjectHash: visitorHash,
      score: result.score,
      decision: result.decision,
      reasons: [...new Set([...(previous?.reasons || []), ...result.reasons])],
      policyVersion: String(policy.version || DEFAULT_POLICY_VERSION),
      expiresAt: now + 5 * 60_000
    };
    decisions.set(cacheKey, item, { ttl: item.expiresAt - now });
    delta.push(item);
    updated.push(item);
  }
  if (delta.length > 100_000) delta.splice(0, delta.length - 100_000);
  const result = { accepted: accepted.length, ignored: inputs.length - accepted.length, decisions: updated };
  Object.defineProperty(result, 'acceptedEvents', { value: accepted, enumerable: false });
  return result;
}

function evaluate(siteKey, visitorHash) {
  return decisions.get(key(siteKey, visitorHash)) || {
    sequence,
    siteKey,
    subjectType: 'visitor',
    subjectHash: visitorHash,
    score: 0,
    decision: 'allow',
    reasons: [],
    policyVersion: DEFAULT_POLICY_VERSION,
    expiresAt: Date.now() + 60_000
  };
}

function listDelta(siteKey, cursor = 0, limit = 1000) {
  const safeCursor = Math.max(0, Number(cursor) || 0);
  const items = delta.filter(item => item.siteKey === siteKey && item.sequence > safeCursor).slice(0, limit);
  return { cursor: items.at(-1)?.sequence || safeCursor, items };
}

function resetForTests() {
  decisions.clear();
  eventIds.clear();
  sequence = 0;
  delta.length = 0;
}

function setSequenceFloor(value) {
  sequence = Math.max(sequence, Number(value) || 0);
}

function hydrate(items = [], now = Date.now()) {
  let restored = 0;
  for (const item of items) {
    const expiresAt = new Date(item.expiresAt || item.expires_at || 0).getTime();
    if (!item.siteKey || !item.subjectHash || expiresAt <= now) continue;
    const normalized = {
      sequence: Number(item.sequence) || 0,
      siteKey: String(item.siteKey),
      subjectType: String(item.subjectType || 'visitor'),
      subjectHash: String(item.subjectHash),
      score: Math.max(0, Math.min(100, Number(item.score) || 0)),
      decision: String(item.decision || 'allow'),
      reasons: Array.isArray(item.reasons) ? item.reasons : [],
      policyVersion: String(item.policyVersion || DEFAULT_POLICY_VERSION),
      expiresAt
    };
    decisions.set(key(normalized.siteKey, normalized.subjectHash), normalized, { ttl: expiresAt - now });
    sequence = Math.max(sequence, normalized.sequence);
    restored += 1;
  }
  return restored;
}

module.exports = { DEFAULT_POLICY_VERSION, applyEvents, evaluate, listDelta, setSequenceFloor, hydrate, resetForTests };
