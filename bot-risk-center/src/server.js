'use strict';

const app = require('./app');
const { PORT, LISTEN_HOST } = require('./config/env');
const StorageService = require('./services/StorageService');
const AlertService = require('./services/AlertService');
const MaintenanceService = require('./services/MaintenanceService');
const DriveBackupService = require('./services/DriveBackupService');
const RuleBackupService = require('./services/RuleBackupService');

let server;

StorageService.initialize()
  .then(() => {
    AlertService.start();
    MaintenanceService.start();
    DriveBackupService.start();
    RuleBackupService.start();
    server = app.listen(PORT, LISTEN_HOST, () => {
      console.log(`机器人风险中心已启动：http://${LISTEN_HOST}:${PORT}`);
    });
  })
  .catch(error => {
    console.error('机器人风险中心初始化失败：', error?.stack || error);
    process.exit(1);
  });

async function shutdown(signal) {
  console.log(`收到 ${signal}，正在停止机器人风险中心…`);
  try {
    if (server) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    AlertService.stop();
    MaintenanceService.stop();
    DriveBackupService.stop();
    RuleBackupService.stop();
    await StorageService.close();
    process.exit(0);
  } catch (error) {
    console.error('机器人风险中心停止失败：', error?.stack || error);
    process.exit(1);
  }
}

process.once('SIGINT', () => { void shutdown('SIGINT'); });
process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
