'use strict';

const { formatAlertLink, formatContactLine, safeHttpUrl } = require('./AlertService');

const MAX_TELEGRAM_CONTENT_LENGTH = 3500;
const ALERT_CHUNK_DELAY_MS = 1500;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function cleanText(value, maxLength = 500) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim().slice(0, maxLength)
    .replace(/([_*\[\]()`])/g, '\\$1');
}

function formatBeijingTime(value = Date.now()) {
  const date = value ? new Date(value) : new Date();
  const safeDate = Number.isNaN(date.getTime()) ? new Date() : date;
  return safeDate.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
}

function splitSummary(header, blocks, maxLength = MAX_TELEGRAM_CONTENT_LENGTH) {
  if (!blocks.length) return [header];
  const chunks = [];
  let current = header;
  for (const block of blocks) {
    const addition = `\n\n${block}`;
    if (Array.from(current + addition).length > maxLength && current !== header) {
      chunks.push(current);
      current = `${header}${addition}`;
    } else current += addition;
  }
  if (current !== header) chunks.push(current);
  return chunks;
}

function splitDetailEntries(header, entries, maxLength = MAX_TELEGRAM_CONTENT_LENGTH) {
  if (!entries.length) return [{ content: header, entries: [] }];
  const chunks = [];
  let content = header;
  let chunkEntries = [];
  for (const entry of entries) {
    const addition = `\n\n${entry.text}`;
    if (Array.from(content + addition).length > maxLength && chunkEntries.length) {
      chunks.push({ content, entries: chunkEntries });
      content = `${header}${addition}`;
      chunkEntries = [entry];
    } else {
      content += addition;
      chunkEntries.push(entry);
    }
  }
  chunks.push({ content, entries: chunkEntries });
  return chunks;
}

function partnerAlertOptions(items = []) {
  const unique = [];
  const seen = new Set();
  for (const item of items) {
    const contact = String(item?.contact || '').replace(/[\r\n\t]+/g, ' ').trim();
    if (!contact || seen.has(contact)) continue;
    seen.add(contact);
    unique.push({ label: `📋 复制：${String(item?.name || `站点 ${item?.id || ''}`).trim()}`, text: contact });
  }
  return {
    copyButtons: unique,
    barkUrl: items.map(item => safeHttpUrl(item?.url)).find(Boolean) || '',
    barkCopy: unique.map(button => `${button.label.replace(/^📋 复制：/, '')}：${button.text}`).join('\n')
  };
}

async function sendChunks(sendAdminAlert, title, eventType, chunks) {
  const deliveries = [];
  for (let index = 0; index < chunks.length; index += 1) {
    if (index > 0) await sleep(ALERT_CHUNK_DELAY_MS);
    const partTitle = chunks.length > 1 ? `${title}（${index + 1}/${chunks.length}）` : title;
    const chunk = typeof chunks[index] === 'string' ? { content: chunks[index], entries: [] } : chunks[index];
    deliveries.push(await sendAdminAlert(partTitle, chunk.content, {
      eventType,
      ...partnerAlertOptions(chunk.entries.map(entry => entry.item))
    }));
  }
  return deliveries;
}

function partnerLines(item) {
  const backlinkUrl = safeHttpUrl(item.backlink_url) || safeHttpUrl(item.url);
  const lines = [
    `站点名称：${cleanText(item.name || `#${item.id}`, 100)}`,
    `站点域名：${formatAlertLink(item.domain || item.url || '未填写', item.domain || item.url, { allowDomain: true })}`,
    `站点网址：${formatAlertLink(item.url || '未填写', item.url)}`,
    `反链检测网址：${formatAlertLink(backlinkUrl || item.backlink_url || item.url || '未填写', backlinkUrl)}`
  ];
  if (!safeHttpUrl(item.backlink_url) && safeHttpUrl(item.url)) lines.push('说明：未单独配置，默认检测站点网址');
  lines.push(formatContactLine('友链站长联系方式', item.contact));
  return lines;
}

function pingDetail(item, index) {
  const failedCount = Number(item.ping_failed_count || 0);
  let reason = item.failure_reason || item.error || '无';
  let action = '连通正常，无需处理';
  if (item.task_error) action = '任务执行异常，未静默计入正常结果';
  else if (item.skipped) action = item.reason || '连通性免检，未执行探活';
  else if (item.alert_event === 'ping_first_failure') action = '首次异常，继续展示并等待下一轮复检';
  else if (item.alert_event === 'ping_offline') action = '已标记失效并从前台隐藏';
  else if (item.alert_event === 'ping_recovered') {
    reason = '无';
    action = '本轮恢复，失败次数已清零并重新展示';
  } else if (failedCount > 0 || item.ping_status === 'unreachable') action = '持续异常，保留失败次数并等待后续复检';
  const identity = partnerLines(item);
  return [
    `${index + 1}. ${identity[0]}`,
    ...identity.slice(1),
    `连续失败次数：${failedCount}`,
    `失败原因：${cleanText(reason || '无')}`,
    `检测时间：${formatBeijingTime(item.checked_at || item.last_ping_at)}`,
    `处理结果：${cleanText(action)}`
  ].join('\n');
}

async function sendPingInspectionSummary(report, sendAdminAlert, taskLabel = '站点连通性探活', options = {}) {
  if (typeof sendAdminAlert !== 'function') return { sent: false, reason: 'missing_sender' };
  const results = Array.isArray(report?.results) ? report.results : [];
  const details = options.includeAllResults === true ? results : results.filter(item => item?.alert_event);
  if (!options.includeAllResults && details.length === 0) return { sent: false, reason: 'no_state_changes' };
  const header = `任务类型：${cleanText(taskLabel)}\n检测时间：${formatBeijingTime()}\n本次探活：${Number(report.target_total ?? results.length)} 个\n正常：${Number(report.normal || 0)} 个\n首次异常：${Number(report.first_failure || 0)} 个\n持续异常：${Number(report.ongoing_failure || 0)} 个\n达到三次失败：${Number(report.reached_dead || 0)} 个\n本轮恢复：${Number(report.recovered || 0)} 个\n任务执行异常：${Number(report.task_errors || 0)} 个`;
  const entries = details.map((item, index) => ({ text: pingDetail(item, index), item }));
  const chunks = splitDetailEntries(header, entries);
  const deliveries = await sendChunks(sendAdminAlert, '⚡ 链群健康体检汇总', 'ping_inspection_summary', chunks);
  return { sent: deliveries.some(item => item?.sent), chunks: chunks.length, deliveries };
}

function backlinkDetail(item, index) {
  const failedCount = Number(item.failed_check_count || 0);
  const lostCount = Number(item.lost_count || 0);
  const checkedPage = item.traffic_skipped ? '' : safeHttpUrl(item.checked_url) || safeHttpUrl(item.url);
  let result = item.result_text || item.failure_reason || item.error || '反链巡检完成';
  let action = '反链正常，无需处理';
  if (item.traffic_skipped) action = '按流量免检规则跳过反链拉取，状态维持正常';
  else if (item.task_error || item.blocked) action = '任务执行异常，已单独计入汇总，请人工检查';
  else if (item.backlink_status === 'protected') action = '暂时无法自动判断，不按掉链处理';
  else if (item.alert_event === 'backlink_lost') action = '已记录掉链并从前台隐藏';
  else if (item.backlink_status === 'lost') action = '仍维持掉链状态，等待人工处理或后续恢复';
  else if (item.alert_event === 'backlink_first_unreachable') action = '首次网络异常，暂不判定掉链，等待下一轮复检';
  else if (item.alert_event === 'backlink_dead') action = '达到三次网络失败，进入死站退避并等待深度复活';
  else if (item.backlink_status === 'unreachable' || item.backlink_status === 'dead') action = '持续网络异常，保留失败次数并等待后续复检';
  else if (item.alert_event === 'backlink_recovered') action = '已恢复反链正常状态并重新展示';
  if (item.traffic_skipped) result = `近24小时存在有效入站流量（${Number(item.traffic_24h || 0)} IP）`;
  const identity = partnerLines(item);
  return [
    `${index + 1}. ${identity[0]}`,
    ...identity.slice(1),
    `本轮实际检测页面：${item.traffic_skipped ? '未发起网络请求' : formatAlertLink(checkedPage || '未填写', checkedPage)}`,
    `近24h有效入站：${Number(item.traffic_24h || 0)} IP`,
    `连续网络失败次数：${failedCount}`,
    `累计掉链次数：${lostCount}`,
    `检测结果：${cleanText(result)}`,
    `检测时间：${formatBeijingTime(item.checked_at || item.last_checked_at)}`,
    `处理结果：${cleanText(action)}`
  ].join('\n');
}

async function sendBacklinkInspectionSummary(report, sendAdminAlert, taskLabel = '每日反链巡检', options = {}) {
  if (typeof sendAdminAlert !== 'function') return { sent: false, reason: 'missing_sender' };
  const results = Array.isArray(report?.results) ? report.results : [];
  const details = options.includeAllResults === true ? results : results.filter(item => item?.alert_event);
  if (!options.includeAllResults && details.length === 0) return { sent: false, reason: 'no_state_changes' };
  const header = `任务类型：${cleanText(taskLabel)}\n检测时间：${formatBeijingTime()}\n纳入本次任务：${Number(report.target_total ?? results.length)} 个\n24h流量免检：${Number(report.traffic_skipped || 0)} 个\n实际网络巡检：${Number(report.network_checked || 0)} 个\n反链正常：${Number(report.normal || 0)} 个\n防护页/无法判定：${Number(report.protected || 0)} 个\n新增确认掉链：${Number(report.newly_lost || 0)} 个\n仍处于掉链：${Number(report.still_lost || 0)} 个\n首次网络异常：${Number(report.first_network_failure || 0)} 个\n持续网络异常：${Number(report.ongoing_network_failure || 0)} 个\n达到三次网络失败：${Number(report.reached_dead || 0)} 个\n本轮恢复：${Number(report.recovered || 0)} 个\n任务执行异常：${Number(report.task_errors || 0)} 个`;
  const entries = details.map((item, index) => ({ text: backlinkDetail(item, index), item }));
  const chunks = splitDetailEntries(header, entries);
  const deliveries = await sendChunks(sendAdminAlert, '🔍 反链巡检汇总', 'backlink_inspection_summary', chunks);
  return { sent: deliveries.some(item => item?.sent), chunks: chunks.length, deliveries };
}

async function sendSingleBacklinkResult(link, result, sendAdminAlert) {
  if (!result?.alert_event || typeof sendAdminAlert !== 'function') return { sent: false, reason: 'no_state_change' };
  const titles = {
    backlink_lost: '🔴 反向友链掉链告警',
    backlink_first_unreachable: '🟡 反链网络异常',
    backlink_dead: '🔴 反链网络失联',
    backlink_recovered: '🟢 反向友链恢复'
  };
  const item = { ...link, ...result };
  return sendAdminAlert(titles[result.alert_event] || '反链状态变化', backlinkDetail(item, 0), {
    eventType: result.alert_event,
    ...partnerAlertOptions([item])
  });
}

async function sendSinglePingResult(link, result, sendAdminAlert) {
  if (!result?.alert_event || typeof sendAdminAlert !== 'function') return { sent: false, reason: 'no_state_change' };
  const titles = { ping_first_failure: '🟡 站点连通性预警', ping_offline: '🔴 站点连通失效', ping_recovered: '🟢 站点连通恢复' };
  const item = { ...link, ...result };
  return sendAdminAlert(titles[result.alert_event] || '站点连通状态变化', pingDetail(item, 0), {
    eventType: result.alert_event,
    ...partnerAlertOptions([item])
  });
}

function backlinkResultAction(result = {}) {
  if (result.exempted) return '反链免检，未执行巡检';
  if (result.backlink_status === 'protected') return '防护页拦截，暂不按掉链处理';
  if (result.alert_event === 'backlink_lost') return '已记录掉链并从前台隐藏';
  if (result.alert_event === 'backlink_recovered') return '已恢复反链并重新展示';
  if (result.alert_event === 'backlink_dead') return '达到三次网络失败，进入死站退避';
  if (Number(result.failed_check_count || 0) > 0) return '已记录网络失败并等待后续复检';
  return '反链正常，无需处理';
}

function pingResultAction(result = {}) {
  if (result.skipped) return '连通性免检，未执行探活';
  if (result.alert_event === 'ping_offline') return '达到三次失败，已标记失效并从前台隐藏';
  if (result.alert_event === 'ping_recovered') return '连通已恢复，失败次数清零并重新展示';
  if (Number(result.ping_failed_count || 0) > 0) return '已记录连通失败并等待后续复检';
  return '网站连通正常';
}

async function sendCombinedSingleResult(link, result, sendAdminAlert) {
  const backlink = result?.backlink || {};
  const connectivity = result?.connectivity || {};
  if ((!backlink.alert_event && !connectivity.alert_event) || typeof sendAdminAlert !== 'function') {
    return { sent: false, reason: 'no_state_change' };
  }
  const changes = [backlink.alert_event ? '反链状态发生变化' : '', connectivity.alert_event ? '连通状态发生变化' : ''].filter(Boolean);
  const content = [
    ...partnerLines(link),
    `检测时间：${formatBeijingTime(result.checked_at)}`,
    '',
    '一、反链状态',
    `当前状态：${cleanText(backlink.result_text || backlink.backlink_status || '未知')}`,
    `连续网络失败次数：${Number(backlink.failed_check_count || 0)}`,
    `累计掉链次数：${Number(backlink.lost_count || 0)}`,
    `本轮实际检测页面：${backlink.exempted ? '反链免检，未发起请求' : formatAlertLink(backlink.checked_url || link.backlink_url || link.url, backlink.checked_url || link.backlink_url || link.url)}`,
    `检测结果：${cleanText(backlink.failure_reason || backlink.result_text || '反链检查完成')}`,
    `处理结果：${cleanText(backlinkResultAction(backlink))}`,
    '',
    '二、连通状态',
    `当前状态：${cleanText(connectivity.result_text || connectivity.ping_status || '未知')}`,
    `连续失败次数：${Number(connectivity.ping_failed_count || 0)}`,
    `失败原因：${cleanText(connectivity.failure_reason || connectivity.error || '无')}`,
    `处理结果：${cleanText(pingResultAction(connectivity))}`,
    '',
    `本轮变化：${changes.join('；')}`
  ].join('\n');
  return sendAdminAlert('🔎 单站联合检测告警', content, {
    eventType: 'combined_single_inspection',
    ...partnerAlertOptions([link])
  });
}

module.exports = {
  splitSummary,
  sendPingInspectionSummary,
  sendBacklinkInspectionSummary,
  sendSingleBacklinkResult,
  sendSinglePingResult,
  sendCombinedSingleResult
};
