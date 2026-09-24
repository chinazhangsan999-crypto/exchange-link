'use strict';

const BackupService = require('../services/TelegramBackupService');
const { ok, fail, safeApiErrorMessage } = require('../utils/http');

async function getStatus(req, res) {
  try { return ok(res, await BackupService.getStatus()); }
  catch (error) { return fail(res, safeApiErrorMessage(error, '读取备份状态失败'), 500); }
}

async function saveSettings(req, res) {
  try {
    const body = req.body || {};
    return ok(res, await BackupService.saveConfig({
      enabled: ['1', 'true', 'on'].includes(String(body.enabled).toLowerCase()),
      botToken: String(body.botToken || '').trim(),
      chatId: String(body.chatId || '').trim(),
      partSizeMiB: Number(body.partSizeMiB || 18),
      clearToken: body.clearToken === true
    }), '备份 Bot 设置已保存');
  } catch (error) { return fail(res, safeApiErrorMessage(error, '保存备份设置失败')); }
}

async function testConnection(req, res) {
  try { return ok(res, await BackupService.testConnection(), '备份 Bot 测试成功'); }
  catch (error) { return fail(res, safeApiErrorMessage(error, '备份 Bot 测试失败'), 502); }
}

async function runNow(req, res) {
  try {
    const result = await BackupService.startBackup();
    return ok(res, result, result.started ? '备份任务已启动' : '备份任务正在执行');
  } catch (error) { return fail(res, safeApiErrorMessage(error, '启动备份任务失败'), 502); }
}

async function retryPending(req, res) {
  try { return ok(res, await BackupService.resumePendingBackups(), '失败分片重试完成'); }
  catch (error) { return fail(res, safeApiErrorMessage(error, '重试失败'), 502); }
}

module.exports = { getStatus, saveSettings, testConnection, runNow, retryPending };
