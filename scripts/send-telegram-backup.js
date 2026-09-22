'use strict';

const path = require('path');
const BackupService = require('../src/services/TelegramBackupService');

const source = process.argv[2];
if (!source) {
  console.error('缺少待发送的 SQLite 备份路径');
  process.exit(2);
}

BackupService.prepareAndUpload(path.resolve(source), { removeSourceAfterEncryption: true })
  .then(result => console.log(JSON.stringify(result)))
  .catch(error => { console.error(error.message || error); process.exitCode = 1; });
