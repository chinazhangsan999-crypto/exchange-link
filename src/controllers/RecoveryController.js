'use strict';

const RecoveryModel = require('../models/RecoveryModel');
const RecoveryService = require('../services/RecoveryService');
const { ok, fail, isUniqueConstraintError } = require('../utils/http');

const idOf = value => {
  const id = Number.parseInt(value, 10);
  if (!Number.isInteger(id) || id < 1) throw new Error('记录 ID 不正确');
  return id;
};

const action = handler => async (req, res) => {
  try { return await handler(req, res); }
  catch (error) {
    if (isUniqueConstraintError(error)) return fail(res, '该地址或 DNS 记录已经存在', 409);
    return fail(res, error.message || '恢复系统操作失败');
  }
};

const getPublicManifest = action(async (_req, res) => {
  res.set({ 'Cache-Control': 'private, no-store', 'X-Robots-Tag': 'noindex, nofollow' });
  return ok(res, await RecoveryService.getPublicManifest());
});

const getOverview = action(async (_req, res) => ok(res, await RecoveryService.overview()));
const saveSettings = action(async (req, res) => ok(res, await RecoveryService.updateSettings(req.body || {}), '恢复系统设置已保存'));

const createDomain = action(async (req, res) => {
  const input = RecoveryService.validateDomainInput(req.body || {});
  const domain = await RecoveryModel.createDomain(input);
  await RecoveryModel.addAudit('domain.create', { id: domain.id, url: domain.url });
  return ok(res, domain, '恢复线路已新增');
});

const updateDomain = action(async (req, res) => {
  const id = idOf(req.params.id);
  if (!await RecoveryModel.getDomain(id)) return fail(res, '恢复线路不存在', 404);
  const domain = await RecoveryModel.updateDomain(id, RecoveryService.validateDomainInput(req.body || {}));
  await RecoveryModel.addAudit('domain.update', { id, url: domain.url });
  return ok(res, domain, '恢复线路已更新');
});

const deleteDomain = action(async (req, res) => {
  const id = idOf(req.params.id);
  const domain = await RecoveryModel.getDomain(id);
  if (!domain) return fail(res, '恢复线路不存在', 404);
  await RecoveryModel.deleteDomain(id);
  await RecoveryModel.addAudit('domain.delete', { id, url: domain.url });
  return ok(res, null, '恢复线路已删除');
});

const probeDomain = action(async (req, res) => ok(res, await RecoveryService.probeAndSave(idOf(req.params.id)), '恢复线路检测完成'));
const probeAll = action(async (_req, res) => ok(res, await RecoveryService.probeAll(), '全部恢复线路检测完成'));

const createBootstrap = action(async (req, res) => {
  const record = await RecoveryModel.createBootstrapRecord(RecoveryService.validateBootstrapInput(req.body || {}));
  await RecoveryModel.addAudit('bootstrap.create', { id: record.id, recordName: record.record_name });
  return ok(res, record, 'Bootstrap DNS 已新增');
});

const updateBootstrap = action(async (req, res) => {
  const id = idOf(req.params.id);
  if (!await RecoveryModel.getBootstrapRecord(id)) return fail(res, 'Bootstrap DNS 不存在', 404);
  const record = await RecoveryModel.updateBootstrapRecord(id, RecoveryService.validateBootstrapInput(req.body || {}));
  await RecoveryModel.addAudit('bootstrap.update', { id, recordName: record.record_name });
  return ok(res, record, 'Bootstrap DNS 已更新');
});

const deleteBootstrap = action(async (req, res) => {
  const id = idOf(req.params.id);
  const record = await RecoveryModel.getBootstrapRecord(id);
  if (!record) return fail(res, 'Bootstrap DNS 不存在', 404);
  await RecoveryModel.deleteBootstrapRecord(id);
  await RecoveryModel.addAudit('bootstrap.delete', { id, recordName: record.record_name });
  return ok(res, null, 'Bootstrap DNS 已删除');
});

const saveCloudflare = action(async (req, res) => ok(res, await RecoveryService.saveCloudflareCredentials(req.body || {}), '恢复系统 DNS 凭据已保存'));
const ensureKey = action(async (_req, res) => { await RecoveryService.ensureCurrentKey(); return ok(res, await RecoveryService.keyStatus(), '当前签名密钥已就绪'); });
const generateNextKey = action(async (_req, res) => ok(res, await RecoveryService.generateNextKey(), '下一代签名密钥已生成'));
const promoteNextKey = action(async (_req, res) => ok(res, await RecoveryService.promoteNextKey(), '下一代密钥已提升为当前密钥'));

const createDraft = action(async (_req, res) => ok(res, await RecoveryService.createDraft(), '恢复清单草稿已生成'));
const publishRelease = action(async (req, res) => ok(res, await RecoveryService.publishRelease(idOf(req.params.id)), '恢复清单发布完成'));
const rollbackRelease = action(async (req, res) => ok(res, await RecoveryService.rollbackTo(idOf(req.params.id)), '历史内容已用新版本重新发布'));

const diagnoseDoh = action(async (req, res) => {
  const id = idOf(req.params.id);
  const record = await RecoveryModel.getBootstrapRecord(id);
  if (!record) return fail(res, 'Bootstrap DNS 不存在', 404);
  return ok(res, { record, results: await RecoveryService.diagnoseDoh(record.record_name) }, 'DoH 回读完成');
});

module.exports = {
  getPublicManifest,
  getOverview,
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
  ensureKey,
  generateNextKey,
  promoteNextKey,
  createDraft,
  publishRelease,
  rollbackRelease,
  diagnoseDoh
};
