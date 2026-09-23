'use strict';

const path = require('path');

async function main() {
  const projectRoot = path.resolve(process.cwd());
  const database = require(path.join(projectRoot, 'src', 'config', 'database'));
  const FrontendModel = require(path.join(projectRoot, 'src', 'models', 'CloudflareFrontendModel'));
  const FrontendService = require(path.join(projectRoot, 'src', 'services', 'CloudflarePublicFrontendService'));
  try {
    const workers = (await FrontendModel.listWorkers()).filter(worker => worker.hostname);
    const results = [];
    for (const worker of workers) {
      try {
        const result = await FrontendService.redeployWorker(Number(worker.id));
        results.push({ id: worker.id, hostname: worker.hostname, worker: worker.worker_name, ok: true, health: result.health });
      } catch (error) {
        results.push({ id: worker.id, hostname: worker.hostname, worker: worker.worker_name, ok: false, error: String(error.message || error) });
      }
    }
    console.log(JSON.stringify({ total: results.length, succeeded: results.filter(item => item.ok).length, results }));
    if (results.some(item => !item.ok)) process.exitCode = 1;
  } finally {
    await database.closeDatabase();
  }
}

main().catch(error => {
  console.error(error.message || error);
  process.exitCode = 1;
});
