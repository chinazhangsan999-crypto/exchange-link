'use strict';

const MAX_TELEGRAM_CONTENT_LENGTH = 3500;
const ALERT_CHUNK_DELAY_MS = 1500;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function cleanText(value, maxLength = 180) {
  return String(value || '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim()
    .slice(0, maxLength)
    .replace(/([_*\[\]()`])/g, '\\$1');
}

function formatBeijingTime() {
  return new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
}

function splitSummary(header, blocks, maxLength = MAX_TELEGRAM_CONTENT_LENGTH) {
  if (!blocks.length) return [];
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

function pingBlock(item, index) {
  const labels = {
    ping_first_failure: ['🟡 首次异常站点', '继续展示，等待下次复检'],
    ping_offline: ['🔴 连续三次失败站点', '已从前台自动隐藏'],
    ping_recovered: ['🟢 本轮恢复站点', '已恢复正常并重新展示']
  };
  const [heading, action] = labels[item.alert_event] || ['站点状态变化', '已记录'];
  const status = item.alert_event === 'ping_first_failure'
    ? '首次探活失败（1/3）'
    : item.alert_event === 'ping_offline'
      ? '连续失败（3/3）'
      : `恢复正常（恢复前失败 ${Number(item.previous_failed_count || 0)} 次）`;
  const failureLine = item.alert_event === 'ping_recovered'
    ? ''
    : `\n失败原因：${cleanText(item.failure_reason || '网络异常')}`;
  return `${heading} #${index + 1}\n站点名称：${cleanText(item.name || `#${item.id}`, 100)}\n站点地址：${cleanText(item.url, 500)}\n当前状态：${status}${failureLine}\n处理结果：${action}`;
}

async function sendPingInspectionSummary(report, sendAdminAlert, taskLabel = '站点连通性探活') {
  if (typeof sendAdminAlert !== 'function') return { sent: false, reason: 'missing_sender' };
  const results = Array.isArray(report?.results) ? report.results : [];
  const events = results.filter(item => item?.alert_event);
  if (!events.length) return { sent: false, reason: 'no_state_changes' };
  const firstFailures = events.filter(item => item.alert_event === 'ping_first_failure');
  const offline = events.filter(item => item.alert_event === 'ping_offline');
  const recovered = events.filter(item => item.alert_event === 'ping_recovered');
  const normal = results.filter(item => item.ping_status === 'ok' && !item.error && !item.skipped && item.alert_event !== 'ping_recovered').length;
  const header = `任务类型：${taskLabel}\n检测时间：${formatBeijingTime()}\n本次探活：${results.length} 个\n正常：${normal} 个\n首次异常：${firstFailures.length} 个\n达到三次失败：${offline.length} 个\n本轮恢复：${recovered.length} 个`;
  const ordered = [...firstFailures, ...offline, ...recovered];
  const chunks = splitSummary(header, ordered.map(pingBlock));
  const deliveries = await sendChunks(sendAdminAlert, '⚡ 链群健康体检汇总', 'ping_inspection_summary', chunks);
  return { sent: deliveries.some(item => item?.sent), chunks: chunks.length, deliveries };
}

function backlinkBlock(item, index) {
  const labels = {
    backlink_lost: ['🔴 新增确认掉链', '页面可访问，但未发现本站链接', '已记录掉链并从前台隐藏'],
    backlink_first_unreachable: ['🟡 首次网络异常', item.failure_reason || '网络异常', '暂不判定掉链，等待下次复检'],
    backlink_dead: ['🔴 连续三次网络失联', item.failure_reason || '网络异常', '已进入死站退避，等待深度复活'],
    backlink_recovered: ['🟢 本轮恢复', '重新检测到本站链接', '已恢复反链正常状态']
  };
  const [heading, result, action] = labels[item.alert_event] || ['反链状态变化', item.failure_reason || '—', '已记录'];
  const count = ['backlink_first_unreachable', 'backlink_dead'].includes(item.alert_event)
    ? `\n当前次数：${Number(item.failed_check_count || 0)}/3`
    : '';
  return `${heading} #${index + 1}\n站点名称：${cleanText(item.name || `#${item.id}`, 100)}\n站点地址：${cleanText(item.url, 500)}\n检测页面：${cleanText(item.checked_url || item.url, 500)}${count}\n检测结果：${cleanText(result)}\n处理结果：${action}`;
}

async function sendBacklinkInspectionSummary(report, sendAdminAlert, taskLabel = '每日反链巡检') {
  if (typeof sendAdminAlert !== 'function') return { sent: false, reason: 'missing_sender' };
  const results = Array.isArray(report?.results) ? report.results : [];
  const events = results.filter(item => item?.alert_event);
  if (!events.length) return { sent: false, reason: 'no_state_changes' };
  const lost = events.filter(item => item.alert_event === 'backlink_lost');
  const firstFailures = events.filter(item => item.alert_event === 'backlink_first_unreachable');
  const dead = events.filter(item => item.alert_event === 'backlink_dead');
  const recovered = events.filter(item => item.alert_event === 'backlink_recovered');
  const normal = results.filter(item => item.backlink_status === 'valid' && !item.error && !item.exempted && item.alert_event !== 'backlink_recovered').length;
  const protectedCount = results.filter(item => item.backlink_status === 'protected').length;
  const networkErrors = results.filter(item => item.error).length;
  const header = `任务类型：${taskLabel}\n检测时间：${formatBeijingTime()}\n本次巡检：${results.length} 个\n反链正常：${normal} 个\n防护页/无法判定：${protectedCount} 个\n本轮网络异常：${networkErrors} 个\n首次网络异常：${firstFailures.length} 个\n新增确认掉链：${lost.length} 个\n连续三次网络失联：${dead.length} 个\n本轮恢复：${recovered.length} 个`;
  const ordered = [...lost, ...firstFailures, ...dead, ...recovered];
  const chunks = splitSummary(header, ordered.map(backlinkBlock));
  const deliveries = await sendChunks(sendAdminAlert, '🔍 反链巡检汇总', 'backlink_inspection_summary', chunks);
  return { sent: deliveries.some(item => item?.sent), chunks: chunks.length, deliveries };
}

module.exports = {
  splitSummary,
  sendPingInspectionSummary,
  sendBacklinkInspectionSummary
};
