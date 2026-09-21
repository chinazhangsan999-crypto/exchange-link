'use strict';

const { LRUCache } = require('lru-cache');

const decisions = new LRUCache({ max: 100000, ttl: 24 * 60 * 60_000 });
const challengeBypasses = new LRUCache({ max: 100000, ttl: 4 * 60 * 60_000 });
let cursor = 0;

function setMany(items = [], now = Date.now()) {
  let applied = 0;
  for (const item of items) {
    const subjectHash = String(item?.subjectHash || item?.subject_hash || '');
    const expiresAt = Number(item?.expiresAt || item?.expires_at || 0);
    const sequence = Number(item?.sequence || 0);
    if (!subjectHash || expiresAt <= now || sequence <= 0) continue;
    const previous = decisions.get(subjectHash);
    if (previous && Number(previous.sequence) >= sequence) continue;
    const decision = {
      sequence,
      score: Number(item.score) || 0,
      decision: String(item.decision || 'allow'),
      reasons: Array.isArray(item.reasons) ? item.reasons.map(String) : [],
      policyVersion: String(item.policyVersion || item.policy_version || ''),
      expiresAt
    };
    decisions.set(subjectHash, decision, { ttl: Math.max(1, expiresAt - now) });
    cursor = Math.max(cursor, sequence);
    applied += 1;
  }
  return applied;
}

function get(subjectHash, now = Date.now()) {
  const item = decisions.get(String(subjectHash || ''));
  if (!item || item.expiresAt <= now) return null;
  return item;
}

function markChallengePassed(subjectHash, now = Date.now()) {
  challengeBypasses.set(String(subjectHash || ''), now, { ttl: 4 * 60 * 60_000 });
}

function hasChallengeBypass(subjectHash) {
  return challengeBypasses.has(String(subjectHash || ''));
}

function getCursor() { return cursor; }
function clear() {
  decisions.clear();
  challengeBypasses.clear();
  cursor = 0;
}
function resetForTests() { clear(); }

module.exports = { setMany, get, markChallengePassed, hasChallengeBypass, getCursor, clear, resetForTests };
