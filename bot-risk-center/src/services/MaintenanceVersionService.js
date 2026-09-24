'use strict';

const NPM_PACKAGES = Object.freeze({
  'aws-route53-sdk': '@aws-sdk/client-route-53',
  archiver: 'archiver',
  'async-mutex': 'async-mutex',
  axios: 'axios',
  bcryptjs: 'bcryptjs',
  cheerio: 'cheerio',
  'connect-sqlite3': 'connect-sqlite3',
  'csv-parse': 'csv-parse',
  express: 'express',
  'express-session': 'express-session',
  jsonwebtoken: 'jsonwebtoken',
  'lru-cache': 'lru-cache',
  multer: 'multer',
  'node-cron': 'node-cron',
  'node-postgres': 'pg',
  'node-redis': 'redis',
  pino: 'pino',
  sqlite3: 'sqlite3',
  'svg-captcha': 'svg-captcha',
  tldts: 'tldts',
  'ua-parser-js': 'ua-parser-js',
  wrangler: 'wrangler'
});

const RUNTIME_INVENTORY_PROJECTS = new Set([
  'caddy', 'crowdsec', 'postgresql', 'redis-server',
  'cloudflare-workerd', 'cloudflare-workers-sdk',
  'alicloud-dns-sdk', 'alicloud-openapi-client', 'tencentcloud-dnspod-sdk'
]);

function trim(value) {
  return String(value || '').trim();
}

function normalizeSemver(value) {
  const match = trim(value).match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]), prerelease: match[4] || '' };
}

function compareSemver(left, right) {
  const a = normalizeSemver(left);
  const b = normalizeSemver(right);
  if (!a || !b) return null;
  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] !== b[key]) return a[key] > b[key] ? 1 : -1;
  }
  if (a.prerelease === b.prerelease) return 0;
  if (!a.prerelease) return 1;
  if (!b.prerelease) return -1;
  return a.prerelease.localeCompare(b.prerelease);
}

function sourceForProject(project) {
  const key = trim(project?.projectKey);
  if (project?.integrationMode === 'reference') return { kind: 'reference' };
  if (project?.integrationMode === 'signal_source') return { kind: 'signal_source' };
  if (NPM_PACKAGES[key]) return { kind: 'npm', packageName: NPM_PACKAGES[key] };
  if (RUNTIME_INVENTORY_PROJECTS.has(key)) return { kind: 'runtime_inventory' };
  return { kind: 'github_release' };
}

function evaluateMaintenanceVersion(project, release = {}) {
  const installed = trim(project?.installedVersion);
  const latest = trim(release.version || project?.latestVersion);
  const source = release.source || sourceForProject(project).kind;

  if (trim(release.error)) return 'error';
  if (source === 'reference' || project?.integrationMode === 'reference') return 'reference';
  if (source === 'signal_source' || project?.integrationMode === 'signal_source') return 'monitor_only';
  if (/managed/i.test(installed)) return 'managed';
  if (/^(?:docker:)?latest$/i.test(installed)) return 'untracked';
  if (source === 'runtime_inventory') return installed ? 'unverifiable' : 'untracked';
  if (!installed) return 'untracked';
  if (!latest) return 'unknown';

  const comparison = compareSemver(installed, latest);
  if (comparison === null) return 'unverifiable';
  if (comparison === 0) return 'current';
  if (comparison > 0) return 'version_ahead';
  if (trim(project?.followedVersion).replace(/^v/i, '') === latest.replace(/^v/i, '')) return 'followed';
  if (trim(project?.ignoredVersion).replace(/^v/i, '') === latest.replace(/^v/i, '')) return 'ignored';
  return 'update_available';
}

module.exports = { NPM_PACKAGES, compareSemver, evaluateMaintenanceVersion, sourceForProject };
