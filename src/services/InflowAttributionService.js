'use strict';

const { LRUCache } = require('lru-cache');

const ATTRIBUTION_TTL_MS = 30 * 60 * 1000;
const attributions = new LRUCache({ max: 100000, ttl: ATTRIBUTION_TTL_MS });

function normalize(attribution) {
  const visitId = String(attribution?.visitId || '');
  const sourcePartnerId = Number(attribution?.sourcePartnerId);
  if (!visitId || !Number.isSafeInteger(sourcePartnerId) || sourcePartnerId <= 0) return null;
  return { visitId, sourcePartnerId };
}

function remember(visitorId, attribution) {
  const normalized = normalize(attribution);
  const key = String(visitorId || '');
  if (!key || !normalized) return false;
  attributions.set(key, normalized);
  return true;
}

function recall(visitorId) {
  const attribution = attributions.get(String(visitorId || ''));
  return attribution ? { ...attribution } : null;
}

function forget(visitorId) {
  attributions.delete(String(visitorId || ''));
}

module.exports = { ATTRIBUTION_TTL_MS, remember, recall, forget };
