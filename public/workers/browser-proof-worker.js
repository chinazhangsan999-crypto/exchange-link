'use strict';

function hex(buffer) {
  return [...new Uint8Array(buffer)].map(value => value.toString(16).padStart(2, '0')).join('');
}

function hasLeadingZeroBits(hexDigest, difficultyBits) {
  const fullNibbles = Math.floor(difficultyBits / 4);
  if (!hexDigest.startsWith('0'.repeat(fullNibbles))) return false;
  const remaining = difficultyBits % 4;
  if (!remaining) return true;
  return Number.parseInt(hexDigest[fullNibbles], 16) < (1 << (4 - remaining));
}

self.onmessage = async event => {
  const challenge = event.data || {};
  const encoder = new TextEncoder();
  for (let solution = 0; solution < 20_000_000; solution += 1) {
    const digest = await crypto.subtle.digest(
      'SHA-256',
      encoder.encode(`${challenge.challengeId}:${challenge.salt}:${solution}`)
    );
    if (hasLeadingZeroBits(hex(digest), Number(challenge.difficultyBits) || 10)) {
      self.postMessage({ solution });
      return;
    }
    if (solution > 0 && solution % 5000 === 0) self.postMessage({ progress: solution });
  }
  self.postMessage({ error: 'proof-limit' });
};
