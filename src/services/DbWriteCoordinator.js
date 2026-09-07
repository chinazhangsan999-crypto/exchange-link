'use strict';

/**
 * SQLite 只有一个写入者。该协调器把进程内的写操作串行化，并让实时流量
 * 优先于后台巡检、CSV 同步和维护任务。它只包裹数据库 I/O，绝不能包裹网络请求。
 */
const WRITE_PRIORITIES = Object.freeze({
  traffic: 0,
  interactive: 10,
  background: 20,
  maintenance: 30
});

class DbWriteQueueError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'DbWriteQueueError';
    this.code = code;
  }
}

class DbWriteCoordinator {
  constructor({ maxQueue = 1000, defaultWaitMs = 30000 } = {}) {
    this.maxQueue = maxQueue;
    this.defaultWaitMs = defaultWaitMs;
    this.queue = [];
    this.running = false;
    this.accepting = true;
    this.sequence = 0;
    this.completed = 0;
    this.rejected = 0;
    this.currentLabel = null;
    this.idleWaiters = new Set();
  }

  run(task, { priority = 'interactive', label = 'sqlite write', maxWaitMs } = {}) {
    if (typeof task !== 'function') return Promise.reject(new TypeError('数据库写任务必须是函数'));
    if (!this.accepting) {
      return Promise.reject(new DbWriteQueueError('服务正在停止，拒绝新的数据库写入', 'DB_WRITE_QUEUE_STOPPING'));
    }
    if (this.queue.length >= this.maxQueue) {
      this.rejected += 1;
      return Promise.reject(new DbWriteQueueError('数据库写入队列繁忙，请稍后重试', 'DB_WRITE_QUEUE_FULL'));
    }

    const rank = typeof priority === 'number' ? priority : (WRITE_PRIORITIES[priority] ?? WRITE_PRIORITIES.interactive);
    const waitMs = Math.max(1, Number(maxWaitMs ?? this.defaultWaitMs) || this.defaultWaitMs);

    return new Promise((resolve, reject) => {
      const item = {
        task,
        rank,
        label,
        sequence: this.sequence += 1,
        resolve,
        reject,
        timer: null
      };
      item.timer = setTimeout(() => {
        const index = this.queue.indexOf(item);
        if (index >= 0) {
          this.queue.splice(index, 1);
          this.rejected += 1;
          reject(new DbWriteQueueError(`数据库写入排队超过 ${waitMs}ms`, 'DB_WRITE_QUEUE_TIMEOUT'));
          this.notifyIdleIfNeeded();
        }
      }, waitMs);
      item.timer.unref?.();
      this.queue.push(item);
      this.queue.sort((left, right) => left.rank - right.rank || left.sequence - right.sequence);
      this.pump();
    });
  }

  pump() {
    if (this.running) return;
    const item = this.queue.shift();
    if (!item) {
      this.notifyIdleIfNeeded();
      return;
    }

    this.running = true;
    this.currentLabel = item.label;
    clearTimeout(item.timer);

    Promise.resolve()
      .then(item.task)
      .then(value => {
        this.completed += 1;
        item.resolve(value);
      }, error => {
        this.rejected += 1;
        item.reject(error);
      })
      .finally(() => {
        this.running = false;
        this.currentLabel = null;
        this.pump();
      });
  }

  beginShutdown() {
    this.accepting = false;
    while (this.queue.length) {
      const item = this.queue.shift();
      clearTimeout(item.timer);
      this.rejected += 1;
      item.reject(new DbWriteQueueError('服务正在停止，未开始的数据库写入已取消', 'DB_WRITE_QUEUE_STOPPING'));
    }
    this.notifyIdleIfNeeded();
  }

  getStats() {
    return {
      pending: this.queue.length,
      running: this.running ? 1 : 0,
      currentLabel: this.currentLabel,
      completed: this.completed,
      rejected: this.rejected,
      accepting: this.accepting
    };
  }

  async drain({ timeoutMs = 15000 } = {}) {
    if (!this.running && this.queue.length === 0) return { drained: true, pending: 0 };
    const safeTimeoutMs = Math.max(1, Number(timeoutMs) || 15000);
    let resolveIdle;
    const idlePromise = new Promise(resolve => { resolveIdle = resolve; });
    this.idleWaiters.add(resolveIdle);
    // 在登记监听器和下一行之间队列可能恰好变为空；二次检查避免无谓等到超时。
    if (!this.running && this.queue.length === 0) this.notifyIdleIfNeeded();
    let timeoutId;
    const result = await Promise.race([
      idlePromise.then(() => ({ drained: true })),
      new Promise(resolve => { timeoutId = setTimeout(() => resolve({ drained: false }), safeTimeoutMs); })
    ]);
    clearTimeout(timeoutId);
    this.idleWaiters.delete(resolveIdle);
    return { drained: result.drained, pending: this.queue.length + (this.running ? 1 : 0) };
  }

  notifyIdleIfNeeded() {
    if (this.running || this.queue.length) return;
    for (const resolve of this.idleWaiters) resolve();
    this.idleWaiters.clear();
  }
}

const dbWriteCoordinator = new DbWriteCoordinator();

module.exports = { DbWriteCoordinator, DbWriteQueueError, WRITE_PRIORITIES, dbWriteCoordinator };
