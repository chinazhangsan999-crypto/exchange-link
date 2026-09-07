'use strict';

const axios = require('axios');
const SystemModel = require('../models/SystemModel');

/** 企业微信与 Telegram Webhook 统一告警入口；失败不会阻断主业务。 */
async function sendAdminAlert(title, contentMarkdown) {
  let webhookUrl;
  try {
    webhookUrl = String(await SystemModel.configValue('webhook_url')).trim();
  } catch (error) {
    console.error('[Webhook Alert Error]: 配置读取失败：', error.message);
    return { sent: false, reason: '配置读取失败' };
  }
  if (!webhookUrl) return { sent: false, reason: '未配置 Webhook' };

  let parsed;
  try {
    parsed = new URL(webhookUrl);
  } catch {
    console.error('[Webhook Alert Error]: Webhook 地址格式无效');
    return { sent: false, reason: '地址格式无效' };
  }

  const host = parsed.hostname.toLowerCase();
  const message = String(contentMarkdown || '');
  let payload;
  if (host === 'qyapi.weixin.qq.com' || host.endsWith('.qyapi.weixin.qq.com')) {
    payload = { msgtype: 'markdown', markdown: { content: `### ${title}\n${message}` } };
  } else if (host === 'api.telegram.org' || host.endsWith('.api.telegram.org')) {
    payload = { text: `*${title}*\n\n${message}`, parse_mode: 'Markdown' };
  } else {
    console.error('[Webhook Alert Error]: 仅支持 Telegram 或企业微信机器人地址');
    return { sent: false, reason: '不支持的 Webhook 类型' };
  }

  try {
    await axios.post(webhookUrl, payload, { timeout: 5000 });
    return { sent: true };
  } catch (error) {
    console.error('[Webhook Alert Error]:', error.message);
    return { sent: false, reason: error.message };
  }
}

module.exports = { sendAdminAlert };
