'use strict';

const { IS_PRODUCTION } = require('../config/env');

// 前端读取队列同样限制为 2；服务端硬上限防止绕过页面脚本后并发抓取。
const MAX_CONCURRENT_READS = 2;
const SLOT_SAFETY_TIMEOUT_MS = 30 * 1000;

// Map 中只保留正在处理的请求；finish/close/安全超时都会删除归零项，不保存历史访客。
const activeReads = new Map();

function limitReadConcurrency(req, res, next) {
  const visitorId = String(req.readAccess?.visitorId || '');
  if (!visitorId) {
    res.set('Cache-Control', 'private, no-store');
    return res.status(403).json({ code: 403, msg: IS_PRODUCTION ? '请求无法处理' : '读取访客身份无效', data: null });
  }

  const activeCount = Number(activeReads.get(visitorId) || 0);
  if (activeCount >= MAX_CONCURRENT_READS) {
    res.set('Cache-Control', 'private, no-store');
    res.set('Retry-After', '1');
    return res.status(429).json({ code: 429, msg: IS_PRODUCTION ? '请求无法处理' : '当前页面读取任务较多，请稍后重试', data: null });
  }

  activeReads.set(visitorId, activeCount + 1);
  let released = false;
  let safetyTimer;
  const release = () => {
    if (released) return;
    released = true;
    clearTimeout(safetyTimer);
    const remaining = Number(activeReads.get(visitorId) || 1) - 1;
    if (remaining > 0) activeReads.set(visitorId, remaining);
    else activeReads.delete(visitorId);
  };

  res.once('finish', release);
  res.once('close', release);
  safetyTimer = setTimeout(release, SLOT_SAFETY_TIMEOUT_MS);
  safetyTimer.unref?.();
  return next();
}

module.exports = {
  MAX_CONCURRENT_READS,
  limitReadConcurrency
};
