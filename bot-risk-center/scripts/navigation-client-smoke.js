'use strict';

const BotRiskClient = require('../../src/services/BotRiskClient');

async function main() {
  const visitorId = `docker-navigation-smoke-${Date.now()}`;
  if (!BotRiskClient.enqueue(visitorId, 'known_ai_crawler', { test: 'navigation-client-smoke' })) {
    throw new Error('navigation risk client is not enabled');
  }
  const flushed = await BotRiskClient.flush();
  if (flushed.sent !== 1) throw new Error(`event flush failed: ${JSON.stringify(flushed)}`);
  const synced = await BotRiskClient.syncDecisions();
  const decision = BotRiskClient.getDecision(visitorId);
  if (!decision || decision.decision !== 'deny' || decision.score !== 100) {
    throw new Error(`unexpected navigation decision: ${JSON.stringify(decision)}`);
  }
  await BotRiskClient.stop();
  process.stdout.write(JSON.stringify({
    ok: true,
    flushed: flushed.sent,
    applied: synced.applied,
    decision: decision.decision,
    score: decision.score,
    enforce: decision.enforce
  }));
}

main().catch(error => {
  console.error(error?.stack || error);
  process.exitCode = 1;
});
