'use strict';

const axios = require('axios');
const SystemModel = require('../models/SystemModel');

const WEBHOOK_TIMEOUT_MS = 10_000;
const RETRY_DELAYS_MS = [400, 1_200];

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function getWebhookErrorDetails(error) {
  return {
    status: Number(error?.response?.status || 0) || null,
    code: error?.code || null,
    description: String(error?.response?.data?.description || error?.message || '未知错误').slice(0, 500)
  };
}

function isRetryableWebhookError(error) {
  const { status, code } = getWebhookErrorDetails(error);
  return !status || status >= 500 || ['ECONNABORTED', 'ETIMEDOUT', 'ECONNRESET', 'ERR_NETWORK'].includes(code);
}

function isTelegramMarkdownError(error) {
  const { status, description } = getWebhookErrorDetails(error);
  return status === 400 && /can't parse entities|parse entities/i.test(description);
}

async function postWithRetry(url, payload) {
  let lastError;
  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt += 1) {
    try {
      await axios.post(url, payload, { timeout: WEBHOOK_TIMEOUT_MS });
      return { sent: true, attempt: attempt + 1 };
    } catch (error) {
      lastError = error;
      if (!isRetryableWebhookError(error) || attempt === RETRY_DELAYS_MS.length) break;
      await sleep(RETRY_DELAYS_MS[attempt]);
    }
  }
  throw lastError;
}

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
  let endpoint = webhookUrl;
  let payload;
  let telegramPayload = null;
  if (host === 'qyapi.weixin.qq.com' || host.endsWith('.qyapi.weixin.qq.com')) {
    payload = { msgtype: 'markdown', markdown: { content: `### ${title}\n${message}` } };
  } else if (host === 'api.telegram.org' || host.endsWith('.api.telegram.org')) {
    const chatId = parsed.searchParams.get('chat_id');
    if (!chatId) {
      console.error('[Webhook Alert Error] provider=telegram status=none code=CONFIG description=缺少 chat_id');
      return { sent: false, reason: 'Telegram 配置缺少 chat_id' };
    }
    // chat_id 只在请求体传递，日志与 API URL 都不保留敏感查询参数。
    parsed.search = '';
    endpoint = parsed.toString();
    telegramPayload = { chat_id: chatId, text: `*${title}*\n\n${message}`, parse_mode: 'Markdown' };
    payload = telegramPayload;
  } else {
    console.error('[Webhook Alert Error]: 仅支持 Telegram 或企业微信机器人地址');
    return { sent: false, reason: '不支持的 Webhook 类型' };
  }

  try {
    return await postWithRetry(endpoint, payload);
  } catch (error) {
    // Telegram 动态 URL、名称等偶尔会触发 Markdown 实体解析错误；保留正常 Markdown，
    // 仅在该类 400 时无格式重发一次，防止告警丢失。
    if (telegramPayload && isTelegramMarkdownError(error)) {
      try {
        return await postWithRetry(endpoint, {
          chat_id: telegramPayload.chat_id,
          text: `${title}\n\n${message}`
        });
      } catch (fallbackError) {
        error = fallbackError;
      }
    }
    const details = getWebhookErrorDetails(error);
    console.error(`[Webhook Alert Error] provider=${host} status=${details.status || 'none'} code=${details.code || 'none'} description=${details.description}`);
    return {
      sent: false,
      reason: details.status ? `Webhook 返回 HTTP ${details.status}` : 'Webhook 网络请求失败'
    };
  }
}

module.exports = { sendAdminAlert };
