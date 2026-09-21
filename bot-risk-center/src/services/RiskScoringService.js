'use strict';

const DECISIONS = Object.freeze({
  ALLOW: 'allow',
  OBSERVE: 'observe',
  SILENT_CHALLENGE: 'silent_challenge',
  STRONG_CHALLENGE: 'strong_challenge',
  DENY: 'deny'
});

const SIGNAL_WEIGHTS = Object.freeze({
  cloudflare_confirmed_bot: 100,
  verified_search_bot: 100,
  known_ai_crawler: 100,
  token_replay: 70,
  sequential_detail_scan: 80,
  high_concurrency: 45,
  botd_detected: 35,
  webdriver_detected: 35,
  browser_automation_confirmed: 100,
  script_user_agent: 60,
  trapdoor_hit: 30,
  repeated_trapdoor: 60,
  challenge_failed: 40,
  missing_fetch_metadata: 10,
  valid_browser_access: -20,
  valid_read_token: -15,
  challenge_passed: -40,
  browser_challenge_passed: -10,
  normal_dwell: -10,
  outbound_interaction: -15
});

const HARD_DENY_SIGNALS = new Set([
  'cloudflare_confirmed_bot',
  'verified_search_bot',
  'known_ai_crawler',
  'browser_automation_confirmed'
]);

function decisionForScore(score) {
  if (score >= 90) return DECISIONS.DENY;
  if (score >= 75) return DECISIONS.STRONG_CHALLENGE;
  if (score >= 50) return DECISIONS.SILENT_CHALLENGE;
  if (score >= 25) return DECISIONS.OBSERVE;
  return DECISIONS.ALLOW;
}

function evaluate(events = [], previousScore = 0) {
  const reasons = [];
  let score = Number(previousScore) || 0;
  let hardDeny = false;
  for (const event of events) {
    const signal = String(event?.signal || event?.eventType || '');
    if (!Object.hasOwn(SIGNAL_WEIGHTS, signal)) continue;
    score += SIGNAL_WEIGHTS[signal];
    if (!reasons.includes(signal)) reasons.push(signal);
    if (HARD_DENY_SIGNALS.has(signal)) hardDeny = true;
  }
  score = Math.max(0, Math.min(100, score));
  return {
    score,
    decision: hardDeny ? DECISIONS.DENY : decisionForScore(score),
    reasons
  };
}

module.exports = { DECISIONS, SIGNAL_WEIGHTS, HARD_DENY_SIGNALS, decisionForScore, evaluate };
