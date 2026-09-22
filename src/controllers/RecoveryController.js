'use strict';

const RecoveryModel = require('../models/RecoveryModel');
const RecoveryService = require('../services/RecoveryService');
const { ok, fail, isUniqueConstraintError } = require('../utils/http');

const idOf = value => {
  const id = Number.parseInt(value, 10);
  if (!Number.isInteger(id) || id < 1) throw new Error('记录 ID 不正确');
  return id;
};
const profileIdOf = req => idOf(req.params.profileId || req.query.profileId || req.body?.profileId || 1);

const action = handler => async (req, res) => {
  try { return await handler(req, res); }
  catch (error) {
    if (isUniqueConstraintError(error)) return fail(res, '该地址或 DNS 记录已经存在', 409);
    return fail(res, error.message || '恢复系统操作失败');
  }
};

const getPublicManifest = action(async (req, res) => {
  res.set({ 'Cache-Control': 'private, no-store', 'X-Robots-Tag': 'noindex, nofollow' });
  return ok(res, await RecoveryService.getPublicManifest(req.trustedFrontendOrigin || ''));
});

const getOverview = action(async (req, res) => ok(res, await RecoveryService.overview(profileIdOf(req))));
const listProfiles = action(async (_req, res) => ok(res, await RecoveryModel.listProfiles()));
const createProfile = action(async (req, res) => ok(res, await RecoveryModel.createProfile(req.body || {}), '恢复方案已创建'));
const saveSettings = action(async (req, res) => ok(res, await RecoveryService.updateSettings(req.body || {}, profileIdOf(req)), '恢复系统设置已保存'));

const createDomain = action(async (req, res) => {
  const input = RecoveryService.validateDomainInput(req.body || {});
  const profileId = profileIdOf(req);
  const domain = await RecoveryModel.createDomain(input, profileId);
  await RecoveryModel.addAudit('domain.create', { id: domain.id, url: domain.url }, true, '', profileId);
  return ok(res, domain, '恢复线路已新增');
});

const updateDomain = action(async (req, res) => {
  const id = idOf(req.params.id);
  const profileId = profileIdOf(req);
  if (!await RecoveryModel.getDomain(id, profileId)) return fail(res, '恢复线路不存在', 404);
  const domain = await RecoveryModel.updateDomain(id, RecoveryService.validateDomainInput(req.body || {}), profileId);
  await RecoveryModel.addAudit('domain.update', { id, url: domain.url }, true, '', profileId);
  return ok(res, domain, '恢复线路已更新');
});

const deleteDomain = action(async (req, res) => {
  const id = idOf(req.params.id);
  const profileId = profileIdOf(req);
  const domain = await RecoveryModel.getDomain(id, profileId);
  if (!domain) return fail(res, '恢复线路不存在', 404);
  await RecoveryModel.deleteDomain(id, profileId);
  await RecoveryModel.addAudit('domain.delete', { id, url: domain.url }, true, '', profileId);
  return ok(res, null, '恢复线路已删除');
});

const probeDomain = action(async (req, res) => ok(res, await RecoveryService.probeAndSave(idOf(req.params.id), profileIdOf(req)), '恢复线路检测完成'));
const probeAll = action(async (req, res) => ok(res, await RecoveryService.probeAll(profileIdOf(req)), '全部恢复线路检测完成'));

const createBootstrap = action(async (req, res) => {
  const profileId = profileIdOf(req);
  const record = await RecoveryModel.createBootstrapRecord(await RecoveryService.validateBootstrapConfiguration(req.body || {}, profileId), profileId);
  await RecoveryModel.addAudit('bootstrap.create', { id: record.id, recordName: record.record_name }, true, '', profileId);
  return ok(res, record, 'Bootstrap DNS 已新增');
});

const updateBootstrap = action(async (req, res) => {
  const id = idOf(req.params.id);
  const profileId = profileIdOf(req);
  if (!await RecoveryModel.getBootstrapRecord(id, profileId)) return fail(res, 'Bootstrap DNS 不存在', 404);
  const record = await RecoveryModel.updateBootstrapRecord(id, await RecoveryService.validateBootstrapConfiguration(req.body || {}, profileId), profileId);
  await RecoveryModel.addAudit('bootstrap.update', { id, recordName: record.record_name }, true, '', profileId);
  return ok(res, record, 'Bootstrap DNS 已更新');
});

const deleteBootstrap = action(async (req, res) => {
  const id = idOf(req.params.id);
  const profileId = profileIdOf(req);
  const record = await RecoveryModel.getBootstrapRecord(id, profileId);
  if (!record) return fail(res, 'Bootstrap DNS 不存在', 404);
  await RecoveryModel.deleteBootstrapRecord(id, profileId);
  await RecoveryModel.addAudit('bootstrap.delete', { id, recordName: record.record_name }, true, '', profileId);
  return ok(res, null, 'Bootstrap DNS 已删除');
});

const saveCloudflare = action(async (req, res) => ok(res, await RecoveryService.saveCloudflareCredentials(req.body || {}, profileIdOf(req)), '恢复系统 DNS 凭据已保存'));
const createDnsChannel = action(async (req, res) => ok(res, await RecoveryService.createDnsChannel(req.body || {}, profileIdOf(req)), 'DNS API 通道已新增'));
const updateDnsChannel = action(async (req, res) => ok(res, await RecoveryService.updateDnsChannel(idOf(req.params.id), req.body || {}, profileIdOf(req)), 'DNS API 通道已更新'));
const testDnsChannel = action(async (req, res) => ok(res, await RecoveryService.testDnsChannel(idOf(req.params.id), profileIdOf(req)), 'DNS API 通道验证成功'));
const listDnsChannelZones = action(async (req, res) => ok(res, await RecoveryService.listDnsChannelZones(idOf(req.params.id), profileIdOf(req))));
const deleteDnsChannel = action(async (req, res) => {
  await RecoveryService.deleteDnsChannel(idOf(req.params.id), profileIdOf(req));
  return ok(res, null, 'DNS API 通道已删除');
});
const ensureKey = action(async (req, res) => { const profileId=profileIdOf(req); await RecoveryService.ensureCurrentKey(profileId); return ok(res, await RecoveryService.keyStatus(profileId), '当前签名密钥已就绪'); });
const generateNextKey = action(async (req, res) => ok(res, await RecoveryService.generateNextKey(profileIdOf(req)), '下一代签名密钥已生成'));
const promoteNextKey = action(async (req, res) => ok(res, await RecoveryService.promoteNextKey(profileIdOf(req)), '下一代密钥已提升为当前密钥'));

const createDraft = action(async (req, res) => ok(res, await RecoveryService.createDraft({ profileId: profileIdOf(req) }), '恢复清单草稿已生成'));
const publishRelease = action(async (req, res) => ok(res, await RecoveryService.publishRelease(idOf(req.params.id), profileIdOf(req)), '恢复清单发布完成'));
const rollbackRelease = action(async (req, res) => ok(res, await RecoveryService.rollbackTo(idOf(req.params.id), profileIdOf(req)), '历史内容已用新版本重新发布'));

const diagnoseDoh = action(async (req, res) => {
  const id = idOf(req.params.id);
  const profileId = profileIdOf(req);
  const record = await RecoveryModel.getBootstrapRecord(id, profileId);
  if (!record) return fail(res, 'Bootstrap DNS 不存在', 404);
  return ok(res, { record, results: await RecoveryService.diagnoseDoh(record.record_name, profileId, id) }, 'DoH 回读完成');
});

const createLookupRoute = action(async (req, res) => {
  const profileId = profileIdOf(req);
  const input = RecoveryService.validateLookupRouteInput(req.body || {});
  if (!await RecoveryModel.getResolver(input.resolverId)) return fail(res, 'DNS 服务商不存在', 404);
  if (!await RecoveryModel.getBootstrapRecord(input.bootstrapId, profileId)) return fail(res, 'Bootstrap TXT 不属于当前方案', 404);
  return ok(res, await RecoveryModel.createLookupRoute(input, profileId), 'DNS/TXT 查询线路已添加');
});
const deleteLookupRoute = action(async (req, res) => {
  await RecoveryModel.deleteLookupRoute(idOf(req.params.id), profileIdOf(req));
  return ok(res, null, 'DNS/TXT 查询线路已删除');
});

module.exports = {
  getPublicManifest,
  getOverview,
  listProfiles,
  createProfile,
  saveSettings,
  createDomain,
  updateDomain,
  deleteDomain,
  probeDomain,
  probeAll,
  createBootstrap,
  updateBootstrap,
  deleteBootstrap,
  saveCloudflare,
  createDnsChannel,
  updateDnsChannel,
  testDnsChannel,
  listDnsChannelZones,
  deleteDnsChannel,
  ensureKey,
  generateNextKey,
  promoteNextKey,
  createDraft,
  publishRelease,
  rollbackRelease,
  diagnoseDoh,
  createLookupRoute,
  deleteLookupRoute
};
