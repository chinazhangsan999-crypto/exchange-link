'use strict';

const { SIGNAL_WEIGHTS, HARD_DENY_SIGNALS } = require('./RiskScoringService');

const DEFINITIONS = Object.freeze({
  cloudflare_confirmed_bot: ['边缘确认机器人', 'edge', 'not_connected', 'high', '等待可信 Cloudflare 机器人字段接入'],
  verified_search_bot: ['已验证搜索蜘蛛', 'identity', 'not_connected', 'high', '等待反向 DNS、正向 DNS 或签名验证器'],
  known_ai_crawler: ['已知 AI 爬虫', 'identity', 'connected', 'medium', '根据维护的 AI 爬虫 UA 目录识别；UA 可伪造'],
  token_replay: ['读取凭证重放', 'credential', 'partial', 'high', '令牌已有次数和访客绑定，重放事件仍需补齐更多失败类型'],
  sequential_detail_scan: ['连续枚举详情', 'behavior', 'connected', 'high', '短时间读取大量不同或连续详情 ID'],
  high_concurrency: ['异常并发读取', 'behavior', 'connected', 'medium', '单访客同时读取超过服务端并发上限'],
  botd_detected: ['BotD 自动化特征', 'browser', 'connected', 'medium', '开源 BotD 基础自动化检测结果'],
  webdriver_detected: ['WebDriver 特征', 'browser', 'connected', 'medium', '浏览器暴露 navigator.webdriver'],
  browser_automation_confirmed: ['浏览器自动化确认', 'browser', 'connected', 'high', 'BotD 与 WebDriver 两类独立信号同时命中'],
  script_user_agent: ['脚本客户端 UA', 'protocol', 'connected', 'medium', '命中常见命令行或程序 HTTP 客户端标识'],
  trapdoor_hit: ['隐藏探针命中', 'behavior', 'connected', 'low', '访问正常页面不可见的探针路径'],
  repeated_trapdoor: ['重复探针命中', 'behavior', 'connected', 'high', '短时间重复访问隐藏探针'],
  challenge_failed: ['静默验证失败', 'challenge', 'connected', 'medium', '计算验证、浏览器验证无效或过期'],
  missing_fetch_metadata: ['缺少 Fetch Metadata', 'protocol', 'connected', 'low', '现代浏览器通常携带，但旧浏览器和隐私工具可能移除'],
  valid_browser_access: ['有效浏览器通行状态', 'positive', 'connected', 'medium', '持有服务端签发的浏览器通行状态'],
  valid_read_token: ['有效读取凭证', 'positive', 'connected', 'medium', '通过正常页面流程取得并使用短效读取令牌'],
  challenge_passed: ['风险验证通过', 'positive', 'connected', 'high', '完成短时计算验证'],
  browser_challenge_passed: ['浏览器挑战通过', 'positive', 'connected', 'high', '完成浏览器环境和计算验证'],
  normal_dwell: ['正常页面停留', 'positive', 'connected', 'low', '页面停留达到真实心跳要求'],
  outbound_interaction: ['真实出站交互', 'positive', 'connected', 'medium', '产生真实的站内出站跳转行为']
});

function list() {
  return Object.entries(DEFINITIONS).map(([signal, values]) => ({
    signal, label: values[0], category: values[1], integrationStatus: values[2],
    confidence: values[3], implementationNote: values[4],
    weight: Number(SIGNAL_WEIGHTS[signal] || 0), hardDeny: HARD_DENY_SIGNALS.has(signal)
  }));
}

module.exports = { list };
