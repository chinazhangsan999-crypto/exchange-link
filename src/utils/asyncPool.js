'use strict';

/**
 * 原生 Promise 动态并发池。
 *
 * - 同时运行的任务不超过 concurrency。
 * - 任一任务完成后立即补入下一个任务，不等待固定批次。
 * - 每个任务都有独立 AbortSignal；超时会先 abort 底层 I/O，再按 rejected 处理。
 * - Worker 必须将 signal 传给支持取消的网络库（例如 Axios）。业务 Worker 应区分
 *   TASK_TIMEOUT 与服务停机取消：前者应持久化失败状态，后者才跳过写库。
 * - 返回值与 Promise.allSettled 一致，并保持输入顺序。
 */
const activeTasks = new Map();
let shutdownRequested = false;
let taskSequence = 0;

function createTaskAbortError(message, code = 'TASK_ABORTED') {
  const error = new Error(message);
  error.name = code === 'TASK_TIMEOUT' ? 'TaskTimeoutError' : 'TaskAbortError';
  error.code = code;
  return error;
}

/** 停机时中止所有仍在底层运行的任务，包括已被 race 超时但尚未 finally 的任务。 */
function abortActivePoolTasks(reason = createTaskAbortError('服务正在停止', 'TASK_ABORTED')) {
  shutdownRequested = true;
  for (const task of activeTasks.values()) {
    if (!task.signal.aborted) task.controller.abort(reason);
  }
  return activeTasks.size;
}

async function drainActivePoolTasks({ timeoutMs = 15000 } = {}) {
  const current = Array.from(activeTasks.values(), task => task.workerPromise);
  if (!current.length) return { drained: true, pending: 0 };
  const waitMs = Math.max(1, Number(timeoutMs) || 15000);
  let timeoutId;
  const result = await Promise.race([
    Promise.allSettled(current).then(() => ({ drained: true })),
    new Promise(resolve => { timeoutId = setTimeout(() => resolve({ drained: false }), waitMs); })
  ]);
  clearTimeout(timeoutId);
  return { drained: result.drained, pending: activeTasks.size };
}

function getActivePoolTaskStats() {
  return { active: activeTasks.size, shutdownRequested };
}

async function runPromisePool(items, concurrency, worker, taskTimeoutMs = 15000) {
  const list = Array.from(items || []);
  const limit = Math.max(1, Math.floor(Number(concurrency) || 1));
  const timeoutMs = Math.max(1, Math.floor(Number(taskTimeoutMs) || 15000));
  const results = new Array(list.length);
  const executing = [];
  let nextIndex = 0;

  function launch(index) {
    if (shutdownRequested) {
      results[index] = { status: 'rejected', reason: createTaskAbortError('服务正在停止', 'TASK_ABORTED') };
      return false;
    }
    let timeoutId;
    let task;
    const controller = new AbortController();
    const taskContext = {
      id: `pool-${Date.now()}-${taskSequence += 1}`,
      index,
      controller,
      signal: controller.signal,
      workerPromise: null
    };
    const workerPromise = Promise.resolve().then(() => worker(list[index], index, controller.signal, taskContext));
    taskContext.workerPromise = workerPromise;
    activeTasks.set(taskContext.id, taskContext);
    // 无论 race 先返回什么，只有底层 Worker 真正结束才从活跃任务表移除。
    workerPromise.finally(() => activeTasks.delete(taskContext.id)).catch(() => {});
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
    return true;
  }

  while (nextIndex < list.length || executing.length > 0) {
    while (nextIndex < list.length && executing.length < limit) {
      const launched = launch(nextIndex);
      nextIndex += 1;
      if (!launched) break;
    }

    if (shutdownRequested && executing.length === 0) {
      while (nextIndex < list.length) {
        results[nextIndex] = { status: 'rejected', reason: createTaskAbortError('服务正在停止', 'TASK_ABORTED') };
        nextIndex += 1;
      }
      break;
    }

    if (executing.length > 0) await Promise.race(executing);
  }

  return results;
}

module.exports = {
  runPromisePool,
  abortActivePoolTasks,
  drainActivePoolTasks,
  getActivePoolTaskStats
};
