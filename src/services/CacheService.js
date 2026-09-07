'use strict';

const { LRUCache } = require('lru-cache');

const memoryCache = new LRUCache({ max: 500, ttl: 30 * 1000 });

function getCachedData(key) {
  return memoryCache.get(key) ?? null;
}

function setCachedData(key, data) {
  memoryCache.set(key, data);
}

function clearPublicCache() {
  memoryCache.delete('public_links_data');
  memoryCache.delete('public_config_data');
  memoryCache.delete('public_showcase_data');
  for (const key of memoryCache.keys()) {
    if (key.startsWith('public_showcase_data_')) memoryCache.delete(key);
  }
  for (const key of memoryCache.keys()) {
    if (key.startsWith('public_ads_data_')) memoryCache.delete(key);
  }
  for (const key of memoryCache.keys()) {
    if (key.startsWith('public_link_detail_')) memoryCache.delete(key);
  }
}

module.exports = { getCachedData, setCachedData, clearPublicCache };
