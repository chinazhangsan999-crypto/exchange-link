'use strict';

const BUSINESS_TIME_ZONE = 'Asia/Shanghai';

/** 将 Date 转换为与 SQLite CURRENT_TIMESTAMP 一致的 UTC 文本格式。 */
function toSqliteUtcTimestamp(value) {
  return value.toISOString().slice(0, 19).replace('T', ' ');
}

/**
 * 返回北京时间自然日 [00:00, 次日 00:00) 对应的 UTC 查询边界。
 * 数据库存储统一使用 SQLite UTC 文本，因此范围条件可直接命中 created_at 索引。
 */
function getLocalDayUtcRange(now = new Date()) {
  const values = Object.fromEntries(
    new Intl.DateTimeFormat('en-CA', {
      timeZone: BUSINESS_TIME_ZONE,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    }).formatToParts(now)
      .filter(part => part.type !== 'literal')
      .map(part => [part.type, part.value])
  );
  const startDate = new Date(Date.UTC(
    Number(values.year),
    Number(values.month) - 1,
    Number(values.day)
  ) - 8 * 60 * 60 * 1000);
  const endDate = new Date(startDate.getTime() + 24 * 60 * 60 * 1000);
  return {
    start: toSqliteUtcTimestamp(startDate),
    end: toSqliteUtcTimestamp(endDate)
  };
}

module.exports = { BUSINESS_TIME_ZONE, toSqliteUtcTimestamp, getLocalDayUtcRange };
