'use strict';

const axios = require('axios');
const cheerio = require('cheerio');
const dns = require('dns').promises;
const net = require('net');
const https = require('https');
const PartnerModel = require('../models/PartnerModel');
const SystemModel = require('../models/SystemModel');
const { parseHostname, isSensitiveNetworkIp } = require('../utils/network');
const { runPromisePool } = require('../utils/asyncPool');

let backlinkCheckInProgress = false;

function notifyChanged(options) {
  if (typeof options?.onDataChanged === 'function') options.onDataChanged();
}

function throwIfAborted(signal) {
  if (!signal?.aborted) return;
  const error = signal.reason instanceof Error ? signal.reason : new Error('巡检任务已取消');
  if (!error.code) error.code = 'TASK_ABORTED';
  throw error;
}

/**
 * asyncPool 超时会以 TaskTimeoutError 作为 signal.reason；Axios 随后通常抛出
 * AbortError / CanceledError（ERR_CANCELED）。这类超时必须计入巡检失败，不能按停机取消跳过写库。
 */
function isTaskTimeoutAbort(error, signal) {
  const reason = signal?.reason;
  return error?.code === 'TASK_TIMEOUT'
    || reason?.code === 'TASK_TIMEOUT'
    || ((error?.name === 'AbortError' || error?.name === 'CanceledError' || error?.code === 'ERR_CANCELED')
      && reason?.code === 'TASK_TIMEOUT');
}

/** 标记无需重试的地址安全错误，避免内网地址触发长时间退避。 */
function blockedBacklinkUrlError(message) {
  const error = new Error(message);
  error.code = 'BACKLINK_URL_BLOCKED';
  return error;
}

/** 在每次请求和重定向前解析 DNS，并返回已经校验的固定公网 IP。 */
async function assertSafeBacklinkUrl(value) {
  let parsed;
  try { parsed = new URL(value); } catch { throw blockedBacklinkUrlError('巡检地址格式无效'); }
  if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password) {
    throw blockedBacklinkUrlError('巡检地址仅允许无认证的 HTTP/HTTPS 地址');
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
    throw blockedBacklinkUrlError('安全策略已拦截本地域名巡检地址');
  }

  if (net.isIP(hostname)) {
    if (isSensitiveNetworkIp(hostname)) throw blockedBacklinkUrlError('安全策略已拦截内网或敏感 IP 巡检地址');
    return { url: parsed, hostname, address: hostname, family: net.isIP(hostname) };
  }

  let records;
  try {
    records = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error('巡检域名 DNS 解析失败');
  }
  if (!records.length || records.some(record => isSensitiveNetworkIp(record.address))) {
    throw blockedBacklinkUrlError('安全策略已拦截解析到内网或敏感 IP 的巡检域名');
  }

  const selected = records.find(record => record.family === 4) || records[0];
  return { url: parsed, hostname, address: selected.address, family: selected.family };
}

/** 固定连接到已经校验的 IP，并保留原始 Host 与 HTTPS SNI，封堵 DNS Rebinding。 */
function createPinnedAxiosConfig(safeTarget, headers = {}) {
  const { url, hostname, address } = safeTarget;
  const ipAuthority = net.isIP(address) === 6 ? `[${address}]` : address;
  const port = url.port ? `:${url.port}` : '';
  const pinnedUrl = `${url.protocol}//${ipAuthority}${port}${url.pathname}${url.search}`;
  const config = {
    url: pinnedUrl,
    proxy: false,
    headers: { ...headers, Host: url.host }
  };
  if (url.protocol === 'https:') {
    config.httpsAgent = new https.Agent({ servername: hostname, rejectUnauthorized: true });
  }
  return config;
}

/**
 * 以浏览器请求头抓取页面；每次重定向均重新执行 SSRF 校验。
 * 网络异常不在当前任务中等待或重试，直接交由下一轮定时巡检处理。
 */
async function fetchWithRetry(url, options = {}) {
  const { signal } = options;
  let targetUrl = String(url);
  for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
    throwIfAborted(signal);
    const safeTarget = await assertSafeBacklinkUrl(targetUrl);
    const pinned = createPinnedAxiosConfig(safeTarget, {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    });
    const response = await axios.request({
      ...pinned,
      method: 'GET',
      timeout: 10000,
      maxRedirects: 0,
      maxContentLength: 5 * 1024 * 1024,
      maxBodyLength: 5 * 1024 * 1024,
      signal,
      validateStatus: () => true
    });

    if ([301, 302, 303, 307, 308].includes(response.status) && response.headers.location) {
      if (redirectCount === 5) throw new Error('巡检地址重定向次数超过限制');
      targetUrl = new URL(response.headers.location, safeTarget.url).href;
      continue;
    }
    if (response.status >= 500) {
      const error = new Error(`HTTP ${response.status}`);
      error.response = response;
      throw error;
    }
    return {
      data: String(response.data || ''),
      status: response.status,
      headers: response.headers,
      finalUrl: safeTarget.url.href
    };
  }

  throw new Error('巡检地址重定向次数超过限制');
}

/** 检查直链、编码 URL 与中转参数是否包含本站域名。 */
function hasBacklink($, myMainDomain) {
  const cleanMainDomain = String(myMainDomain || '')
    .replace(/^(https?:\/\/)?(www\.)?/i, '')
    .replace(/\/.*$/, '')
    .toLowerCase();
  if (!cleanMainDomain) return false;

  let matched = false;
  $('a').each((_, elem) => {
    const rawHref = $(elem).attr('href');
    if (!rawHref) return undefined;
    try {
      if (String(rawHref).toLowerCase().includes(cleanMainDomain)) {
        matched = true;
        return false;
      }
      const decodedHref = decodeURIComponent(rawHref).toLowerCase();
      if (decodedHref.includes(cleanMainDomain)) {
        matched = true;
        return false;
      }
      const parsedUrl = new URL(rawHref, 'https://placeholder.invalid');
      for (const paramValue of parsedUrl.searchParams.values()) {
        let decodedValue = String(paramValue).toLowerCase();
        try { decodedValue = decodeURIComponent(decodedValue); } catch { /* 已解码或编码不完整。 */ }
        if (decodedValue.includes(cleanMainDomain)) {
          matched = true;
          return false;
        }
      }
    } catch {
      // 单个非法 URL 不影响其他锚点。
    }
    return undefined;
  });
  return matched;
}

function resolveUrl(base, relative) {
  try {
    const url = new URL(relative, base);
    return /^https?:$/.test(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

function isProtectedResponse(status, html = '') {
  const text = String(html || '').toLowerCase();
  return [403, 503].includes(Number(status))
    || /cloudflare|just a moment|attention required|security check|captcha|verify you are human|宝塔|防cc|waf|ddos-guard/.test(text);
}

async function updateBacklinkStatus(link, status, checkedUrl, options = {}) {
  throwIfAborted(options.signal);
  const { incrementLostCount = false, backlinkUrl = null } = options;
  if (status === 'lost' && incrementLostCount) {
    await PartnerModel.recordBacklinkLost(link.id, { signal: options.signal });
    notifyChanged(options);
    const lostCount = Number(link.lost_count || 0) + 1;
    if (link.backlink_status !== 'lost' && typeof options.sendAdminAlert === 'function') {
      void options.sendAdminAlert(
        '🔴 反向友链掉链告警',
        `> **站点名称：** ${link.name || `#${link.id}`}\n> **站点网址：** ${link.url || checkedUrl}\n> **累计掉链次数：** ${lostCount}\n> **巡检时间：** ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`
      );
    }
    return { id: link.id, backlink_status: 'lost', failed_check_count: 0, lost_count: lostCount, checked_url: checkedUrl };
  }

  await PartnerModel.recordBacklinkStatus(link.id, status, backlinkUrl, { signal: options.signal });
  notifyChanged(options);
  return {
    id: link.id,
    backlink_status: status,
    failed_check_count: 0,
    lost_count: Number(link.lost_count || 0),
    checked_url: checkedUrl,
    ...(backlinkUrl ? { discovered_backlink_url: true } : {})
  };
}

/** 对 iframe 内容做一次无重试穿透检查。 */
async function hasIframeBacklink($, baseUrl, cleanDomain, myMainDomain, options = {}) {
  const iframes = $('iframe[src]').toArray().slice(0, 10);
  for (const iframe of iframes) {
    const iframeUrl = resolveUrl(baseUrl, $(iframe).attr('src'));
    if (!iframeUrl) continue;
    try {
      const response = await fetchWithRetry(iframeUrl, { signal: options.signal });
      if (!isProtectedResponse(response.status, response.data)
        && (response.data.toLowerCase().includes(cleanDomain) || hasBacklink(cheerio.load(response.data), myMainDomain))) {
        return true;
      }
    } catch (error) {
      throwIfAborted(options.signal);
      // 单个 iframe 失败不影响主页面检测结论。
    }
  }
  return false;
}

/** 检查单个站点的反链，并持久化巡检结论。 */
async function checkSingleBacklink(link, myMainDomain, mySiteName = '', options = {}) {
  throwIfAborted(options.signal);
  if (Number(link.is_exempt) === 1) {
    return {
      id: link.id,
      backlink_status: link.backlink_status || 'valid',
      failed_check_count: 0,
      exempted: true,
      checked_url: null
    };
  }
  const domain = String(myMainDomain || '')
    .replace(/^(https?:\/\/)?(www\.)?/i, '')
    .replace(/\/.*$/, '')
    .toLowerCase();
  const targetUrl = link.backlink_url || link.url;

  try {
    const response = await fetchWithRetry(targetUrl, { signal: options.signal });
    const rawHtml = response.data;
    const checkedUrl = response.finalUrl || targetUrl;
    const $ = cheerio.load(rawHtml);

    if (isProtectedResponse(response.status, rawHtml)) {
      return updateBacklinkStatus(link, 'protected', checkedUrl, options);
    }
    if (hasBacklink($, domain) || rawHtml.toLowerCase().includes(domain)) {
      return updateBacklinkStatus(link, 'valid', checkedUrl, options);
    }
    if (await hasIframeBacklink($, checkedUrl, domain, domain, options)) {
      return updateBacklinkStatus(link, 'valid', checkedUrl, options);
    }

    if (!link.backlink_url) {
      let detailPageUrl = null;
      $('a[href]').each((_, elem) => {
        const text = String($(elem).text() || '').trim();
        const href = String($(elem).attr('href') || '').trim();
        if (!href) return undefined;
        if ((mySiteName && text.includes(mySiteName)) || /\/(site|detail|post|link|friend)(\/|\?|$)/i.test(href)) {
          detailPageUrl = resolveUrl(checkedUrl, href);
          if (detailPageUrl) return false;
        }
        return undefined;
      });

      if (detailPageUrl) {
        const detailResponse = await fetchWithRetry(detailPageUrl, { signal: options.signal });
        const detailHtml = detailResponse.data;
        const $detail = cheerio.load(detailHtml);
        if (isProtectedResponse(detailResponse.status, detailHtml)) {
          return updateBacklinkStatus(link, 'protected', detailPageUrl, options);
        }
        if (hasBacklink($detail, domain)
          || detailHtml.toLowerCase().includes(domain)
          || await hasIframeBacklink($detail, detailPageUrl, domain, domain, options)) {
          return updateBacklinkStatus(link, 'valid', detailPageUrl, { ...options, backlinkUrl: detailPageUrl });
        }
      }
    }

    return updateBacklinkStatus(link, 'lost', targetUrl, { ...options, incrementLostCount: true });
  } catch (error) {
    const timedOut = isTaskTimeoutAbort(error, options.signal);
    // 只有服务停机等非超时取消才跳过写库；超时必须留下异常状态，避免状态假死。
    if (options.signal?.aborted && !timedOut) throwIfAborted(options.signal);
    if (error.code === 'BACKLINK_URL_BLOCKED') {
      await PartnerModel.touchBacklinkCheck(link.id, { signal: options.signal });
      notifyChanged(options);
      return {
        id: link.id,
        backlink_status: link.backlink_status,
        checked_url: targetUrl,
        blocked: true,
        reason: error.message
      };
    }
    if (!timedOut && isProtectedResponse(error.response?.status, error.response?.data)) {
      return updateBacklinkStatus(link, 'protected', targetUrl, options);
    }
    const failedCount = Number(link.failed_check_count || 0) + 1;
    const status = failedCount >= 3 ? 'dead' : 'unreachable';
    await PartnerModel.recordBacklinkFailure(link.id, status, failedCount, {
      signal: options.signal,
      allowAbortedWrite: timedOut
    });
    notifyChanged(options);
    return {
      id: link.id,
      backlink_status: status,
      failed_check_count: failedCount,
      lost_count: Number(link.lost_count || 0),
      checked_url: targetUrl,
      error: timedOut ? '连接超时（任务超过 15 秒）' : error.message
    };
  }
}

async function recordBacklinkCheckError(link, error, options = {}) {
  const timedOut = isTaskTimeoutAbort(error, options.signal);
  if (options.signal?.aborted && !timedOut) throwIfAborted(options.signal);
  const failedCount = Number(link.failed_check_count || 0) + 1;
  const status = failedCount >= 3 ? 'dead' : 'unreachable';
  await PartnerModel.recordBacklinkFailure(link.id, status, failedCount, {
    signal: options.signal,
    allowAbortedWrite: timedOut
  });
  notifyChanged(options);
  return {
    id: link.id,
    backlink_status: status,
    failed_check_count: failedCount,
    lost_count: Number(link.lost_count || 0),
    checked_url: link.backlink_url || link.url,
    error: timedOut ? '连接超时（任务超过 15 秒）' : String(error?.message || error)
  };
}

/** 动态并发巡检；任一槽位完成即补入下一个站点，24h 有流量的站点直接免检。 */
async function checkAllLinksBatch(links, myMainDomain, mySiteName, concurrency = 3, options = {}) {
  const poolSize = Math.max(1, Number(concurrency) || 3);
  const taskTimeoutMs = Math.max(1, Number(options.taskTimeoutMs) || 15000);
  const settled = await runPromisePool(links, poolSize, async (link, _index, signal) => {
    const taskOptions = { ...options, signal };
    try {
      throwIfAborted(signal);
      if (Number(link.is_exempt) === 1) {
        return {
          id: link.id,
          backlink_status: link.backlink_status || 'valid',
          failed_check_count: 0,
          exempted: true,
          checked_url: null
        };
      }
      if (Number(link.traffic_24h) > 0) {
        throwIfAborted(signal);
        await PartnerModel.markTrafficExempt(link.id, { signal });
        notifyChanged(taskOptions);
        return {
          id: link.id,
          backlink_status: 'valid',
          traffic_24h: Number(link.traffic_24h),
          exempted: true,
          checked_url: null
        };
      }
      return await checkSingleBacklink(link, myMainDomain, mySiteName, taskOptions);
    } catch (error) {
      const timedOut = isTaskTimeoutAbort(error, signal);
      if (signal?.aborted && !timedOut) throwIfAborted(signal);
      try {
        return await recordBacklinkCheckError(link, error, taskOptions);
      } catch (persistError) {
        return {
          id: link.id,
          backlink_status: 'unreachable',
          checked_url: link.backlink_url || link.url,
          error: String(persistError?.message || persistError || '巡检任务异常')
        };
      }
    }
  }, taskTimeoutMs);

  return settled.map((result, index) => result.status === 'fulfilled'
    ? result.value
    : {
        id: links[index].id,
        backlink_status: 'unreachable',
        checked_url: links[index].backlink_url || links[index].url,
        error: String(result.reason?.message || result.reason || '巡检任务异常')
      });
}

async function checkAllBacklinks(options = {}) {
  if (backlinkCheckInProgress) return { started: false, reason: '巡检任务正在执行' };
  backlinkCheckInProgress = true;
  try {
    const myMainDomain = parseHostname(await SystemModel.configValue('site_url'));
    const mySiteName = await SystemModel.configValue('site_name');
    if (!myMainDomain) throw new Error('本站地址配置无效，无法进行反链巡检');
    const links = await PartnerModel.listBacklinkInspectionTargets();
    const results = await checkAllLinksBatch(links, myMainDomain, mySiteName, 3, options);
    return { started: true, total: results.length, results };
  } finally {
    backlinkCheckInProgress = false;
  }
}

/** 每日低频检测被常规任务退避的长期 dead 站点。 */
async function checkDeepDeadBacklinks(options = {}) {
  if (backlinkCheckInProgress) return { started: false, reason: '巡检任务正在执行' };
  backlinkCheckInProgress = true;
  try {
    const myMainDomain = parseHostname(await SystemModel.configValue('site_url'));
    const mySiteName = await SystemModel.configValue('site_name');
    if (!myMainDomain) throw new Error('本站地址配置无效，无法进行反链巡检');
    const links = await PartnerModel.listDeepBacklinkRevivalTargets();
    const results = await checkAllLinksBatch(links, myMainDomain, mySiteName, 3, options);
    return { started: true, total: results.length, results };
  } finally {
    backlinkCheckInProgress = false;
  }
}

function isBacklinkCheckInProgress() {
  return backlinkCheckInProgress;
}

module.exports = {
  assertSafeBacklinkUrl,
  createPinnedAxiosConfig,
  fetchWithRetry,
  hasBacklink,
  hasIframeBacklink,
  checkSingleBacklink,
  checkAllLinksBatch,
  checkAllBacklinks,
  checkDeepDeadBacklinks,
  isBacklinkCheckInProgress
};
