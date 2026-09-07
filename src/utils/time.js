'use strict';

/** 将 Date 转换为与 SQLite CURRENT_TIMESTAMP 一致的 UTC 文本格式。 */
function toSqliteUtcTimestamp(value) {
  return value.toISOString().slice(0, 19).replace('T', ' ');
}

/**
 * 返回服务器本地自然日 [00:00, 次日 00:00) 对应的 UTC 查询边界。
 * 数据库存储统一使用 SQLite UTC 文本，因此范围条件可直接命中 created_at 索引。
 */
function getLocalDayUtcRange(now = new Date()) {
  const startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const endDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
  return {
    start: toSqliteUtcTimestamp(startDate),
    end: toSqliteUtcTimestamp(endDate)
  };
}

module.exports = { toSqliteUtcTimestamp, getLocalDayUtcRange };
