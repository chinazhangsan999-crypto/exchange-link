const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { dbWriteCoordinator } = require('../services/DbWriteCoordinator');

// config/database.js 位于 src/config，默认上退两级指向项目根目录数据库。
// DB_PATH 可供测试、容器挂载或多实例部署显式覆盖，避免误建到当前工作目录。
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(__dirname, '..', '..', 'webring.db'));
const DATABASE_PATH = DB_PATH;
const db = new sqlite3.Database(DB_PATH);

// 在任何查询发出前配置共享连接：遇到写锁最多等待 5 秒，避免高并发日志直接 SQLITE_BUSY。
db.configure('busyTimeout', 5000);

const SQLITE_WRITE_RETRY_LIMIT = 3;

const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const isTransientWriteLock = error => /SQLITE_(BUSY|LOCKED)/.test(String(error?.code || error?.message || ''));

/** 仅重试尚未取得写锁的 SQLite 瞬态冲突；所有重试仍在单写入队列内。 */
async function retryTransientWrite(work) {
  let lastError;
  for (let attempt = 0; attempt < SQLITE_WRITE_RETRY_LIMIT; attempt += 1) {
    try {
      return await work();
    } catch (error) {
      lastError = error;
      if (!isTransientWriteLock(error) || attempt === SQLITE_WRITE_RETRY_LIMIT - 1) throw error;
      await delay(75 * (2 ** attempt) + Math.floor(Math.random() * 50));
    }
  }
  throw lastError;
}

/** 将 sqlite 回调 API 封装为 Promise。仅供协调器内部直接执行。 */
const runDirect = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function onRun(error) {
    if (error) reject(error);
    else resolve({ id: this.lastID, changes: this.changes });
  });
});

/**
 * 所有共享连接写入统一进入单写入协调器。第三个参数为可选优先级，不影响旧调用。
 */
const run = (sql, params = [], options = {}) => dbWriteCoordinator.run(
  () => retryTransientWrite(() => runDirect(sql, params)),
  { priority: options.priority || 'interactive', label: options.label || String(sql).split(/\s+/).slice(0, 3).join(' ') }
);

const getDirect = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (error, row) => (error ? reject(error) : resolve(row)));
});

const get = getDirect;

/** 某些 PRAGMA 会写 WAL；需要结果时也必须经过同一写入协调器。 */
const writeGet = (sql, params = [], options = {}) => dbWriteCoordinator.run(
  () => retryTransientWrite(() => getDirect(sql, params)),
  { priority: options.priority || 'maintenance', label: options.label || 'sqlite write pragma' }
);

const all = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (error, rows) => (error ? reject(error) : resolve(rows)));
});

/** 在独立连接中执行原子事务，避免共享连接的并发 BEGIN 冲突。 */
async function withTransactionDirect(work) {
  const transactionDb = new sqlite3.Database(DATABASE_PATH);
  transactionDb.configure('busyTimeout', 5000);
  const txRun = (sql, params = []) => new Promise((resolve, reject) => {
    transactionDb.run(sql, params, function onRun(error) {
      if (error) reject(error);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
  const txGet = (sql, params = []) => new Promise((resolve, reject) => {
    transactionDb.get(sql, params, (error, row) => (error ? reject(error) : resolve(row)));
  });
  const txAll = (sql, params = []) => new Promise((resolve, reject) => {
    transactionDb.all(sql, params, (error, rows) => (error ? reject(error) : resolve(rows)));
  });
  const txClose = () => new Promise((resolve, reject) => {
    transactionDb.close(error => (error ? reject(error) : resolve()));
  });
  let transactionStarted = false;

  try {
    await txRun('PRAGMA foreign_keys = ON');
    // 事务开始即申请写锁，避免先读后写时才突然出现 SQLITE_BUSY。
    await txRun('BEGIN IMMEDIATE TRANSACTION');
    transactionStarted = true;
    const result = await work({ run: txRun, get: txGet, all: txAll });
    await txRun('COMMIT');
    transactionStarted = false;
    return result;
  } catch (error) {
    if (transactionStarted) {
      try {
        await txRun('ROLLBACK');
      } catch (rollbackError) {
        console.error('SQLite 事务回滚失败：', rollbackError.message);
      }
    }
    throw error;
  } finally {
    try {
      await txClose();
    } catch (closeError) {
      console.error('SQLite 事务连接关闭失败：', closeError.message);
    }
  }
}

/**
 * 独立事务连接也要进入同一个协调器，避免 BEGIN IMMEDIATE 与共享连接互相抢写锁。
 * 事务回调仅允许数据库操作；网络请求必须在事务外完成。
 */
function withTransaction(work, options = {}) {
  return dbWriteCoordinator.run(
    () => retryTransientWrite(() => withTransactionDirect(work)),
    { priority: options.priority || 'interactive', label: options.label || 'sqlite transaction', maxWaitMs: options.maxWaitMs }
  );
}

/** 安全关闭全局共享 SQLite 连接。 */
function closeDatabase() {
  return new Promise((resolve, reject) => {
    db.close(error => {
      if (error) reject(error);
      else resolve();
    });
  });
}

module.exports = {
  DB_PATH,
  DATABASE_PATH,
  db,
  run,
  get,
  writeGet,
  all,
  withTransaction,
  closeDatabase
};
