'use strict';

/**
 * 原生 Promise 动态并发池。
 *
 * - 同时运行的任务不超过 concurrency。
 * - 任一任务完成后立即补入下一个任务，不等待固定批次。
 * - 每个任务都有独立 AbortSignal；超时会先 abort 底层 I/O，再按 rejected 处理。
 * - Worker 必须将 signal 传给支持取消的网络库（例如 Axios），并在写库前检查
 *   signal.aborted，避免任务超时后继续落盘。
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
    const controller = new AbortController();
    const workerPromise = Promise.resolve().then(() => worker(list[index], index, controller.signal));
    const timeoutPromise = new Promise((_, reject) => {
      timeoutId = setTimeout(() => {
        const error = new Error(`异步任务执行超时（${timeoutMs}ms）`);
        error.name = 'TaskTimeoutError';
        error.code = 'TASK_TIMEOUT';
        error.taskIndex = index;
        error.timeoutMs = timeoutMs;
        controller.abort(error);
        reject(error);
      }, timeoutMs);
    });

    // Promise.race 先返回超时时，原 Worker 仍可能在响应 abort 的过程中完成；
    // 始终订阅其拒绝，避免成为未处理 Promise 拒绝。
    workerPromise.catch(() => {});

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
