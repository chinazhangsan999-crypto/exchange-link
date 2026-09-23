'use strict';

const StorageService = require('../services/StorageService');

async function snapshot(req, res) {
  return res.json({ code: 200, data: await StorageService.getMaintenanceSnapshot() });
}

async function upstreams(req, res) {
  const data = await StorageService.listMaintenanceProjects();
  return res.json({ code: 200, data: data.map(item => ({
    projectKey: item.projectKey, name: item.name, repository: item.repository,
    integrationMode: item.integrationMode, installedVersion: item.installedVersion,
    usedBy: item.usedBy, componentKind: item.componentKind,
    latestVersion: item.latestVersion, latestReleaseAt: item.latestReleaseAt,
    releaseUrl: item.releaseUrl, lastCheckedAt: item.lastCheckedAt,
    followStatus: item.followStatus, followedVersion: item.followedVersion,
    followedAt: item.followedAt, lastError: item.lastError
  })) });
}

module.exports = { snapshot, upstreams };
