'use strict';

const axios = require('axios');
const SystemModel = require('../models/SystemModel');
const WebhookDeliveryModel = require('../models/WebhookDeliveryModel');

const WEBHOOK_TIMEOUT_MS = 10_000;
const BARK_TIMEOUT_MS = 8_000;
const RETRY_DELAYS_MS = [400, 1_200];
const BARK_RETRY_DELAYS_MS = [800];
// Bark 最终通过 APNs 投递；为标题、分组和 JSON 字段预留空间，正文按 UTF-8 字节安全分段。
const BARK_BODY_MAX_BYTES = 2_500;
const TELEGRAM_COPY_TEXT_MAX_LENGTH = 256;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function cleanInlineText(value, maxLength = 256) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim().slice(0, maxLength);
}

function markdownInlineCode(value) {
  const text = cleanInlineText(value).replace(/[`\\]/g, character => character === '`' ? '＇' : '/');
  return `\`${text}\``;
}

function safeHttpUrl(value, { allowDomain = false } = {}) {
  let candidate = cleanInlineText(value, 2_048);
  if (!candidate) return '';
  if (allowDomain && !/^https?:\/\//i.test(candidate)) candidate = `https://${candidate}`;
  try {
    const parsed = new URL(candidate);
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : '';
  } catch {
    return '';
  }
}

function escapeMarkdownLabel(value) {
  return cleanInlineText(value, 500).replace(/([_*\[\]()`])/g, '\\$1');
}

function formatAlertLink(label, value, options = {}) {
  const url = safeHttpUrl(value, options);
  const text = escapeMarkdownLabel(label || value || '链接');
  if (!url) return text;
  return `[${text}](${url.replace(/[()]/g, character => encodeURIComponent(character))})`;
}

function formatContactLine(label, value) {
  const contact = cleanInlineText(value, TELEGRAM_COPY_TEXT_MAX_LENGTH);
  return contact ? `${label}：${markdownInlineCode(contact)}` : `${label}：未填写`;
}

function splitUtf8Text(value, maxBytes = BARK_BODY_MAX_BYTES) {
  const text = String(value || '');
  if (!text) return [''];
  const chunks = [];
  let current = '';
  for (const character of text) {
    if (Buffer.byteLength(current + character, 'utf8') > maxBytes && current) {
      chunks.push(current);
      current = character;
    } else {
      current += character;
    }
  }
  if (current) chunks.push(current);
  return chunks;
}

function getWebhookErrorDetails(error) {
  return {
    status: Number(error?.response?.status || 0) || null,
    code: error?.code || null,
    description: String(error?.response?.data?.description || error?.message || '未知错误')
      .replace(/https?:\/\/[^\s]+/gi, '[已隐藏地址]').slice(0, 300)
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

function providerForUrl(value) {
  try {
    const host = new URL(String(value || '').trim()).hostname.toLowerCase();
    if (host === 'api.telegram.org' || host.endsWith('.api.telegram.org')) return 'telegram';
    if (host === 'qyapi.weixin.qq.com' || host.endsWith('.qyapi.weixin.qq.com')) return 'wecom';
  } catch { /* invalid configuration is reported by the caller */ }
  return null;
}

async function postWithRetry(url, payload, { timeoutMs, retryDelays }) {
  let lastError;
  let attempts = 0;
  for (let attempt = 0; attempt <= retryDelays.length; attempt += 1) {
    attempts = attempt + 1;
    try {
      const response = await axios.post(url, payload, { timeout: timeoutMs });
      return { sent: true, attemptCount: attempts, statusCode: response.status };
    } catch (error) {
      lastError = error;
      if (!isRetryableWebhookError(error) || attempt === retryDelays.length) break;
      await sleep(retryDelays[attempt]);
    }
  }
  lastError.attemptCount = attempts;
  throw lastError;
}

async function recordDeliverySafely(data) {
  try {
    await WebhookDeliveryModel.recordDelivery(data);
  } catch (error) {
    // 可观测性落库不能反过来阻断巡检、申请、Ping 等主业务。
    console.error('[Webhook Delivery Log Error]:', error?.message || error);
  }
}

async function deliverPrimary(webhookUrl, title, message) {
  const parsed = new URL(webhookUrl);
  const provider = providerForUrl(webhookUrl);
  if (!provider) throw Object.assign(new Error('仅支持 Telegram 或企业微信机器人地址'), { code: 'UNSUPPORTED_PROVIDER' });

  let endpoint = webhookUrl;
  let payload;
  let telegramPayload = null;
  if (provider === 'wecom') {
    payload = { msgtype: 'markdown', markdown: { content: `### ${title}\n${message}` } };
  } else {
    const chatId = parsed.searchParams.get('chat_id');
    if (!chatId) throw Object.assign(new Error('Telegram 配置缺少 chat_id'), { code: 'CONFIG' });
    parsed.search = '';
    endpoint = parsed.toString();
    telegramPayload = {
      chat_id: chatId,
      text: `*${title}*\n\n${message}`,
      parse_mode: 'Markdown'
    };
    payload = telegramPayload;
  }

  try {
    return { provider, ...await postWithRetry(endpoint, payload, { timeoutMs: WEBHOOK_TIMEOUT_MS, retryDelays: RETRY_DELAYS_MS }) };
  } catch (error) {
    if (!telegramPayload || !isTelegramMarkdownError(error)) throw Object.assign(error, { provider });
    const initialAttempts = Number(error.attemptCount || 1);
    try {
      const fallback = await postWithRetry(endpoint, {
        chat_id: telegramPayload.chat_id,
        text: `${title}\n\n${message}`
      },
        { timeoutMs: WEBHOOK_TIMEOUT_MS, retryDelays: RETRY_DELAYS_MS });
      return { provider, ...fallback, attemptCount: initialAttempts + fallback.attemptCount, markdownFallback: true };
    } catch (fallbackError) {
      fallbackError.attemptCount = initialAttempts + Number(fallbackError.attemptCount || 1);
      throw Object.assign(fallbackError, { provider });
    }
  }
}

function barkPushEndpoint(value) {
  const parsed = new URL(String(value || '').trim());
  if (parsed.protocol !== 'https:') throw Object.assign(new Error('Bark 服务地址必须使用 HTTPS'), { code: 'CONFIG' });
  const basePath = parsed.pathname.replace(/\/$/, '');
  parsed.pathname = /\/push$/i.test(basePath) ? basePath : `${basePath}/push`;
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

async function deliverBark({ serverUrl, deviceKey, group, title, message, url, copy }) {
  if (!deviceKey) throw Object.assign(new Error('Bark Device Key 未配置'), { code: 'CONFIG' });
  const endpoint = barkPushEndpoint(serverUrl);
  const parts = splitUtf8Text(message);
  let attemptCount = 0;
  let statusCode = null;
  for (let index = 0; index < parts.length; index += 1) {
    const partTitle = parts.length > 1 ? `${title}（${index + 1}/${parts.length}）` : title;
    const part = parts[index];
    const result = await postWithRetry(endpoint, {
      device_key: deviceKey,
      title: partTitle,
      body: part,
      markdown: part,
      group: group || '网站告警',
      level: 'timeSensitive',
      ...(safeHttpUrl(url) ? { url: safeHttpUrl(url) } : {}),
      ...(cleanInlineText(copy, TELEGRAM_COPY_TEXT_MAX_LENGTH) ? {
        copy: cleanInlineText(copy, TELEGRAM_COPY_TEXT_MAX_LENGTH)
      } : {})
    }, { timeoutMs: BARK_TIMEOUT_MS, retryDelays: BARK_RETRY_DELAYS_MS });
    attemptCount += result.attemptCount;
    statusCode = result.statusCode;
  }
  return { provider: 'bark', sent: true, attemptCount, statusCode, partCount: parts.length };
}

async function loadAlertConfig() {
  const values = await Promise.all([
    SystemModel.configValue('site_name'), SystemModel.configValue('webhook_url'),
    SystemModel.configValue('bark_enabled'), SystemModel.configValue('bark_server_url'),
    SystemModel.configValue('bark_device_key'), SystemModel.configValue('bark_group'),
    SystemModel.configValue('contact_info'), SystemModel.configValue('contact_email')
  ]);
  return {
    siteName: String(values[0] || '').trim() || '网站', webhookUrl: String(values[1] || '').trim(),
    barkEnabled: String(values[2]) === '1', barkServerUrl: String(values[3] || '').trim(),
    barkDeviceKey: String(values[4] || '').trim(), barkGroup: String(values[5] || '').trim() || '网站告警',
    adminContact: [values[6], values[7]].map(value => cleanInlineText(value, TELEGRAM_COPY_TEXT_MAX_LENGTH))
      .find(value => value && !/^请在后台系统设置中填写/.test(value)) || ''
  };
}

function makeFailure(provider, error, attemptCount = 0) {
  const details = getWebhookErrorDetails(error);
  return {
    provider, sent: false, attemptCount: Number(attemptCount || error?.attemptCount || 0),
    statusCode: details.status, errorCode: details.code,
    reason: details.status ? `HTTP ${details.status}` : details.description, errorMessage: details.description
  };
}

/** 主通道成功即结束；仅主通道最终失败时由 Bark 接管。 */
async function sendAdminAlert(title, contentMarkdown, options = {}) {
  const eventType = String(options.eventType || 'system');
  let config;
  try { config = await loadAlertConfig(); }
  catch (error) {
    console.error('[Webhook Alert Error]: 配置读取失败：', error?.message || error);
    return { sent: false, provider: 'config', reason: '配置读取失败' };
  }

  const displayTitle = `【${config.siteName}】${String(title || '系统通知')}`;
  const baseMessage = String(contentMarkdown || '').trim();
  const message = config.adminContact
    ? `${baseMessage}${baseMessage ? '\n\n' : ''}${formatContactLine('本站管理员联系方式', config.adminContact)}`
    : baseMessage;
  const barkCopy = cleanInlineText(options.barkCopy, TELEGRAM_COPY_TEXT_MAX_LENGTH)
    || config.adminContact;
  const primaryProvider = providerForUrl(config.webhookUrl) || 'config';
  let primary;
  if (!config.webhookUrl) {
    primary = { provider: 'config', sent: false, attemptCount: 0, reason: '未配置主告警通道', errorCode: 'CONFIG', errorMessage: '未配置主告警通道' };
    await recordDeliverySafely({ eventType, provider: 'config', success: false, errorCode: primary.errorCode, errorMessage: primary.errorMessage });
  } else {
    const startedAt = Date.now();
    try {
      const result = await deliverPrimary(config.webhookUrl, displayTitle, message);
      primary = { ...result, durationMs: Date.now() - startedAt };
      await recordDeliverySafely({ eventType, provider: result.provider, success: true, attemptCount: result.attemptCount,
        statusCode: result.statusCode, durationMs: primary.durationMs });
      return { sent: true, provider: result.provider, fallback: false, primary };
    } catch (error) {
      primary = { ...makeFailure(error.provider || primaryProvider, error), durationMs: Date.now() - startedAt };
      await recordDeliverySafely({ eventType, provider: primary.provider, success: false, attemptCount: primary.attemptCount,
        statusCode: primary.statusCode, errorCode: primary.errorCode, errorMessage: primary.errorMessage, durationMs: primary.durationMs });
      console.error(`[Webhook Alert Error] provider=${primary.provider} status=${primary.statusCode || 'none'} code=${primary.errorCode || 'none'} description=${primary.errorMessage}`);
    }
  }

  if (options.allowBarkFallback === false || !config.barkEnabled) {
    return { sent: false, provider: primary.provider, fallback: false, primary, reason: primary.reason };
  }
  const startedAt = Date.now();
  try {
    const result = await deliverBark({ serverUrl: config.barkServerUrl, deviceKey: config.barkDeviceKey,
      group: config.barkGroup, title: displayTitle, message,
      url: options.barkUrl, copy: barkCopy });
    const backup = { ...result, durationMs: Date.now() - startedAt };
    await recordDeliverySafely({ eventType, provider: 'bark', isFallback: true, success: true, attemptCount: result.attemptCount,
      statusCode: result.statusCode, durationMs: backup.durationMs });
    return { sent: true, provider: 'bark', fallback: true, primary, backup,
      message: '主告警通道不可用，已通过 Bark 备用通道发送' };
  } catch (error) {
    const backup = { ...makeFailure('bark', error), durationMs: Date.now() - startedAt };
    await recordDeliverySafely({ eventType, provider: 'bark', isFallback: true, success: false, attemptCount: backup.attemptCount,
      statusCode: backup.statusCode, errorCode: backup.errorCode, errorMessage: backup.errorMessage, durationMs: backup.durationMs });
    console.error(`[Bark Alert Error] status=${backup.statusCode || 'none'} code=${backup.errorCode || 'none'} description=${backup.errorMessage}`);
    return { sent: false, provider: 'bark', fallback: true, primary, backup, reason: backup.reason };
  }
}

/** 仅用于后台手动验证 Bark，不触发主通道或故障转移。 */
async function sendBarkTestAlert(title, contentMarkdown, options = {}) {
  let config;
  try { config = await loadAlertConfig(); }
  catch { return { sent: false, provider: 'config', reason: '配置读取失败' }; }
  const displayTitle = `【${config.siteName}】${String(title || 'Bark 测试消息')}`;
  const baseMessage = String(contentMarkdown || '').trim();
  const message = config.adminContact
    ? `${baseMessage}${baseMessage ? '\n\n' : ''}${formatContactLine('本站管理员联系方式', config.adminContact)}`
    : baseMessage;
  const startedAt = Date.now();
  try {
    const result = await deliverBark({ serverUrl: config.barkServerUrl, deviceKey: config.barkDeviceKey,
      group: config.barkGroup, title: displayTitle, message,
      url: options.barkUrl, copy: options.barkCopy || config.adminContact });
    await recordDeliverySafely({ eventType: options.eventType || 'manual_test_bark', provider: 'bark', success: true,
      attemptCount: result.attemptCount, statusCode: result.statusCode, durationMs: Date.now() - startedAt });
    return { sent: true, provider: 'bark', fallback: false };
  } catch (error) {
    const failure = makeFailure('bark', error);
    await recordDeliverySafely({ eventType: options.eventType || 'manual_test_bark', provider: 'bark', success: false,
      attemptCount: failure.attemptCount, statusCode: failure.statusCode, errorCode: failure.errorCode,
      errorMessage: failure.errorMessage, durationMs: Date.now() - startedAt });
    return { sent: false, provider: 'bark', reason: failure.reason };
  }
}

module.exports = {
  sendAdminAlert,
  sendBarkTestAlert,
  providerForUrl,
  safeHttpUrl,
  formatAlertLink,
  formatContactLine
};
