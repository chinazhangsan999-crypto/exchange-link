'use strict';

const MAX_TELEGRAM_CONTENT_LENGTH = 3500;
const ALERT_CHUNK_DELAY_MS = 1500;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function cleanText(value, maxLength = 500) {
  return String(value ?? '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim()
    .slice(0, maxLength)
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
    } else {
      current += addition;
    }
  }
  if (current !== header) chunks.push(current);
  return chunks;
}

async function sendChunks(sendAdminAlert, title, eventType, chunks) {
  const deliveries = [];
  for (let index = 0; index < chunks.length; index += 1) {
    if (index > 0) await sleep(ALERT_CHUNK_DELAY_MS);
    const partTitle = chunks.length > 1 ? `${title}（${index + 1}/${chunks.length}）` : title;
    deliveries.push(await sendAdminAlert(partTitle, chunks[index], { eventType }));
  }
  return deliveries;
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
  } else if (failedCount > 0 || item.ping_status === 'unreachable') {
    action = '持续异常，保留失败次数并等待后续复检';
  }
  return `${index + 1}. 站点名称：${cleanText(item.name || `#${item.id}`, 100)}\n站点网址：${cleanText(item.url)}\n连续失败次数：${failedCount}\n失败原因：${cleanText(reason || '无')}\n检测时间：${formatBeijingTime(item.checked_at || item.last_ping_at)}\n处理结果：${cleanText(action)}`;
}

async function sendPingInspectionSummary(report, sendAdminAlert, taskLabel = '站点连通性探活', options = {}) {
  if (typeof sendAdminAlert !== 'function') return { sent: false, reason: 'missing_sender' };
  const results = Array.isArray(report?.results) ? report.results : [];
  const details = options.includeAllResults === true ? results : results.filter(item => item?.alert_event);
  if (!options.includeAllResults && details.length === 0) return { sent: false, reason: 'no_state_changes' };
  const header = `任务类型：${taskLabel}\n检测时间：${formatBeijingTime()}\n本次探活：${Number(report.target_total ?? results.length)} 个\n正常：${Number(report.normal || 0)} 个\n首次异常：${Number(report.first_failure || 0)} 个\n持续异常：${Number(report.ongoing_failure || 0)} 个\n达到三次失败：${Number(report.reached_dead || 0)} 个\n本轮恢复：${Number(report.recovered || 0)} 个\n任务执行异常：${Number(report.task_errors || 0)} 个`;
  const chunks = splitSummary(header, details.map(pingDetail));
  const deliveries = await sendChunks(sendAdminAlert, '⚡ 链群健康体检汇总', 'ping_inspection_summary', chunks);
  return { sent: deliveries.some(item => item?.sent), chunks: chunks.length, deliveries };
}

function backlinkDetail(item, index) {
  const failedCount = Number(item.failed_check_count || 0);
  const lostCount = Number(item.lost_count || 0);
  const checkedPage = item.traffic_skipped ? '未发起网络请求' : (item.checked_url || item.url || '—');
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
  return `${index + 1}. 站点名称：${cleanText(item.name || `#${item.id}`, 100)}\n站点网址：${cleanText(item.url)}\n检测页面：${cleanText(checkedPage)}\n近24h有效入站：${Number(item.traffic_24h || 0)} IP\n连续网络失败次数：${failedCount}\n累计掉链次数：${lostCount}\n检测结果：${cleanText(result)}\n检测时间：${formatBeijingTime(item.checked_at)}\n处理结果：${cleanText(action)}`;
}

async function sendBacklinkInspectionSummary(report, sendAdminAlert, taskLabel = '每日反链巡检', options = {}) {
  if (typeof sendAdminAlert !== 'function') return { sent: false, reason: 'missing_sender' };
  const results = Array.isArray(report?.results) ? report.results : [];
  const details = options.includeAllResults === true ? results : results.filter(item => item?.alert_event);
  if (!options.includeAllResults && details.length === 0) return { sent: false, reason: 'no_state_changes' };
  const header = `任务类型：${taskLabel}\n检测时间：${formatBeijingTime()}\n纳入本次任务：${Number(report.target_total ?? results.length)} 个\n24h流量免检：${Number(report.traffic_skipped || 0)} 个\n实际网络巡检：${Number(report.network_checked || 0)} 个\n反链正常：${Number(report.normal || 0)} 个\n防护页/无法判定：${Number(report.protected || 0)} 个\n新增确认掉链：${Number(report.newly_lost || 0)} 个\n仍处于掉链：${Number(report.still_lost || 0)} 个\n首次网络异常：${Number(report.first_network_failure || 0)} 个\n持续网络异常：${Number(report.ongoing_network_failure || 0)} 个\n达到三次网络失败：${Number(report.reached_dead || 0)} 个\n本轮恢复：${Number(report.recovered || 0)} 个\n任务执行异常：${Number(report.task_errors || 0)} 个`;
  const chunks = splitSummary(header, details.map(backlinkDetail));
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
  return sendAdminAlert(titles[result.alert_event] || '反链状态变化', backlinkDetail({ ...link, ...result }, 0), { eventType: result.alert_event });
}

async function sendSinglePingResult(link, result, sendAdminAlert) {
  if (!result?.alert_event || typeof sendAdminAlert !== 'function') return { sent: false, reason: 'no_state_change' };
  const titles = {
    ping_first_failure: '🟡 站点连通性预警',
    ping_offline: '🔴 站点连通失效',
    ping_recovered: '🟢 站点连通恢复'
  };
  return sendAdminAlert(titles[result.alert_event] || '站点连通状态变化', pingDetail({ ...link, ...result }, 0), { eventType: result.alert_event });
}

module.exports = {
  splitSummary,
  sendPingInspectionSummary,
  sendBacklinkInspectionSummary,
  sendSingleBacklinkResult,
  sendSinglePingResult
};
