'use strict';

/**
 * 原生 Promise 动态并发池。
 *
 * - 同时运行的任务不超过 concurrency。
 * - 任一任务完成后立即补入下一个任务，不等待固定批次。
 * - 每个任务都有独立超时，超时后按 rejected 处理并立即释放并发槽位。
 * - 返回值与 Promise.allSettled 一致，并保持输入顺序。
 */
async function runPromisePool(items, concurrency, worker, taskTimeoutMs = 15000) {
  const list = Array.from(items || []);
  const limit = Math.max(1, Math.floor(Number(concurrency) || 1));
  const timeoutMs = Math.max(1, Math.floor(Number(taskTimeoutMs) || 15000));
  const results = new Array(list.length);
  const executing = [];
  let nextIndex = 0;

  function launch(index) {
    let timeoutId;
    let task;
    const workerPromise = Promise.resolve().then(() => worker(list[index], index));
    const timeoutPromise = new Promise((_, reject) => {
      timeoutId = setTimeout(() => {
        const error = new Error(`异步任务执行超时（${timeoutMs}ms）`);
        error.name = 'TaskTimeoutError';
        error.code = 'TASK_TIMEOUT';
        error.taskIndex = index;
        error.timeoutMs = timeoutMs;
        reject(error);
      }, timeoutMs);
    });

    task = Promise.race([workerPromise, timeoutPromise])
      .then(
        value => { results[index] = { status: 'fulfilled', value }; },
        reason => { results[index] = { status: 'rejected', reason }; }
      )
      .finally(() => {
        clearTimeout(timeoutId);
        const taskIndex = executing.indexOf(task);
        if (taskIndex !== -1) executing.splice(taskIndex, 1);
      });

    executing.push(task);
  }

  while (nextIndex < list.length || executing.length > 0) {
    while (nextIndex < list.length && executing.length < limit) {
      launch(nextIndex);
      nextIndex += 1;
    }

    if (executing.length > 0) await Promise.race(executing);
  }

  return results;
}

module.exports = { runPromisePool };
