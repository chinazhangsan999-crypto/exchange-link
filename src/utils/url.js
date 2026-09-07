'use strict';

function normalizeUrl(value) {
  const url = String(value || '').trim();
  if (!/^https?:\/\//i.test(url)) throw new Error('网址必须以 http:// 或 https:// 开头');
  return url;
}

function normalizeAnalyticsScriptUrl(value) {
  const parsed = new URL(String(value || '').trim());
  if (parsed.protocol !== 'https:') throw new Error('Umami 脚本地址必须为 HTTPS URL');
  return parsed.href;
}

module.exports = { normalizeUrl, normalizeAnalyticsScriptUrl };
