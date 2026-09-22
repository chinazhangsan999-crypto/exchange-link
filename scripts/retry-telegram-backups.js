'use strict';

const BackupService = require('../src/services/TelegramBackupService');

BackupService.resumePendingBackups()
  .then(result => console.log(JSON.stringify(result)))
  .catch(error => { console.error(error.message || error); process.exitCode = 1; });
