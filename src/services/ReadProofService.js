'use strict';

const crypto = require('crypto');
const { LRUCache } = require('lru-cache');

const PROOF_TTL_MS = 30 * 1000;
const PROOF_DIFFICULTY_BITS = 12;
const MAX_PROOF_SOLUTION = 1_000_000;

const challenges = new LRUCache({
  max: 50000,
  ttl: PROOF_TTL_MS
});

function countLeadingZeroBits(buffer) {
  let bits = 0;
  for (const byte of buffer) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    for (let mask = 0x80; mask > 0 && (byte & mask) === 0; mask >>= 1) bits += 1;
    break;
  }
  return bits;
}

function issueChallenge(visitorId, now = Date.now(), requestedDifficultyBits = PROOF_DIFFICULTY_BITS) {
  const difficultyBits = Math.max(8, Math.min(20, Number(requestedDifficultyBits) || PROOF_DIFFICULTY_BITS));
  const challengeId = crypto.randomBytes(18).toString('base64url');
  const salt = crypto.randomBytes(16).toString('base64url');
  const expiresAt = now + PROOF_TTL_MS;
  challenges.set(challengeId, {
    visitorId: String(visitorId || ''),
    salt,
    difficultyBits,
    expiresAt
  });
  return { challengeId, salt, difficultyBits, expiresAt };
}

function verifyChallenge(visitorId, input = {}, now = Date.now()) {
  const challengeId = String(input.challengeId || '');
  const solution = Number(input.solution);
  const record = challenges.get(challengeId);
  // 挑战无论成功还是失败都立即销毁，避免重放和反复试探。
  if (challengeId) challenges.delete(challengeId);
  if (!record || record.expiresAt <= now) return { ok: false, reason: 'expired' };
  if (record.visitorId !== String(visitorId || '')) return { ok: false, reason: 'visitor_mismatch' };
  if (!Number.isSafeInteger(solution) || solution < 0 || solution > MAX_PROOF_SOLUTION) {
    return { ok: false, reason: 'invalid_solution' };
  }

  const digest = crypto.createHash('sha256')
    .update(`${challengeId}:${record.salt}:${solution}`)
    .digest();
  if (countLeadingZeroBits(digest) < record.difficultyBits) return { ok: false, reason: 'insufficient_work' };
  return { ok: true };
}

module.exports = {
  PROOF_TTL_MS,
  PROOF_DIFFICULTY_BITS,
  MAX_PROOF_SOLUTION,
  countLeadingZeroBits,
  issueChallenge,
  verifyChallenge
};
