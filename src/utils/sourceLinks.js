'use strict';

const { normalizeUrl } = require('./url');

function buildSourceEntryUrls(sourceSid, configuredSiteUrl) {
  const encodedSid = encodeURIComponent(String(sourceSid || '').trim());
  const relativePathUrl = `/r/${encodedSid}`;
  const relativeQueryUrl = `/?sid=${encodedSid}`;
  try {
    const parsed = new URL(normalizeUrl(configuredSiteUrl));
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
      throw new Error('本站地址配置不合法');
    }
    return {
      pathUrl: new URL(relativePathUrl, parsed.origin).href,
      queryUrl: new URL(relativeQueryUrl, parsed.origin).href
    };
  } catch {
    return { pathUrl: relativePathUrl, queryUrl: relativeQueryUrl };
  }
}

module.exports = { buildSourceEntryUrls };
