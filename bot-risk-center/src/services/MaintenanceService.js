'use strict';

const StorageService = require('./StorageService');
const AlertService = require('./AlertService');
const { GITHUB_API_TOKEN } = require('../config/env');

const REQUEST_TIMEOUT_MS = 8000;
const SCHEDULER_INTERVAL_MS = 15 * 60_000;
const CHECK_BATCH_SIZE = 4;
let timer = null;
let initialTimer = null;
let running = false;

function githubHeaders() {
  return {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'webring-bot-risk-center',
    'X-GitHub-Api-Version': '2022-11-28',
    ...(GITHUB_API_TOKEN ? { Authorization: `Bearer ${GITHUB_API_TOKEN}` } : {})
  };
}

async function githubJson(url) {
  const response = await fetch(url, { headers: githubHeaders(), signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`GitHub API ${response.status}`);
  return response.json();
}

async function fetchLatestRelease(repository) {
  const encoded = repository.split('/').map(encodeURIComponent).join('/');
  try {
    const release = await githubJson(`https://api.github.com/repos/${encoded}/releases/latest`);
    return {
      version: String(release.tag_name || release.name || '').slice(0, 120),
      releasedAt: release.published_at || release.created_at || null,
      url: String(release.html_url || `https://github.com/${repository}/releases`).slice(0, 500)
    };
  } catch (releaseError) {
    try {
      const tags = await githubJson(`https://api.github.com/repos/${encoded}/tags?per_page=1`);
      const tag = Array.isArray(tags) ? tags[0] : null;
      if (tag?.name) {
        return { version: String(tag.name).slice(0, 120), releasedAt: null, url: `https://github.com/${repository}/tags` };
      }
      const commits = await githubJson(`https://api.github.com/repos/${encoded}/commits?per_page=1`);
      const commit = Array.isArray(commits) ? commits[0] : null;
      if (!commit?.sha) throw releaseError;
      return {
        version: `commit-${String(commit.sha).slice(0, 7)}`,
        releasedAt: commit.commit?.committer?.date || commit.commit?.author?.date || null,
        url: String(commit.html_url || `https://github.com/${repository}/commits`).slice(0, 500)
      };
    } catch (tagError) {
      return { version: '', releasedAt: null, url: `https://github.com/${repository}`, error: tagError.message || releaseError.message };
    }
  }
}

async function checkUpstreams({ force = false } = {}) {
  if (running) return { skipped: true, reason: 'already_running', items: await StorageService.listMaintenanceProjects() };
  running = true;
  try {
    const settings = await StorageService.getAlertSettings();
    const before = await StorageService.listMaintenanceProjects();
    if (!force) {
      const interval = Math.max(1, settings?.upstreamCheckIntervalHours || 6) * 3600000;
      const due = before.some(item => !item.lastCheckedAt || Date.now() - new Date(item.lastCheckedAt).getTime() >= interval);
      if (!due) return { skipped: true, reason: 'not_due', items: before };
    }
    for (let offset = 0; offset < before.length; offset += CHECK_BATCH_SIZE) {
      const batch = before.slice(offset, offset + CHECK_BATCH_SIZE);
      await Promise.all(batch.map(async project => {
        const release = await fetchLatestRelease(project.repository);
        await StorageService.updateMaintenanceProject(project.projectKey, release);
      }));
    }
    await StorageService.refreshAllSiteAdvisories();
    const items = await StorageService.listMaintenanceProjects();
    const pendingAlerts = items.filter(item => item.followStatus === 'update_available'
      && item.latestVersion && item.latestVersion !== item.alertedVersion);
    if (pendingAlerts.length && await AlertService.notifyUpstreamUpdates(pendingAlerts)) {
      await StorageService.markMaintenanceProjectsAlerted(pendingAlerts);
    }
    return { skipped: false, checked: items.length, updates: pendingAlerts.length, items };
  } finally { running = false; }
}

function start() {
  if (timer) return;
  initialTimer = setTimeout(() => { void checkUpstreams().catch(error => console.error('上游项目检查失败：', error?.stack || error)); }, 60_000);
  initialTimer.unref?.();
  timer = setInterval(() => { void checkUpstreams().catch(error => console.error('上游项目检查失败：', error?.stack || error)); }, SCHEDULER_INTERVAL_MS);
  timer.unref?.();
}

function stop() {
  if (initialTimer) clearTimeout(initialTimer);
  if (timer) clearInterval(timer);
  initialTimer = null; timer = null;
}

module.exports = { start, stop, checkUpstreams, fetchLatestRelease };
