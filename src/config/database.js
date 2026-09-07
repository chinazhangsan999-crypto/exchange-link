const path = require('path');
const sqlite3 = require('sqlite3').verbose();

// config/database.js 位于 src/config，默认上退两级指向项目根目录数据库。
// DB_PATH 可供测试、容器挂载或多实例部署显式覆盖，避免误建到当前工作目录。
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(__dirname, '..', '..', 'webring.db'));
const DATABASE_PATH = DB_PATH;
const db = new sqlite3.Database(DB_PATH);

// 在任何查询发出前配置共享连接：遇到写锁最多等待 5 秒，避免高并发日志直接 SQLITE_BUSY。
db.configure('busyTimeout', 5000);

/** 将 sqlite 回调 API 封装为 Promise。 */
const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function onRun(error) {
    if (error) reject(error);
    else resolve({ id: this.lastID, changes: this.changes });
  });
});

const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (error, row) => (error ? reject(error) : resolve(row)));
});

const all = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (error, rows) => (error ? reject(error) : resolve(rows)));
});

/** 在独立连接中执行原子事务，避免共享连接的并发 BEGIN 冲突。 */
async function withTransaction(work) {
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
  all,
  withTransaction,
  closeDatabase
};
