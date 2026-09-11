'use strict';

const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const source = path.resolve(process.argv[2] || 'webring.db');
const destination = path.resolve(process.argv[3] || `webring-backup-${Date.now()}.db`);
const db = new sqlite3.Database(source);
const backup = db.backup(destination);

backup.step(-1, stepError => {
  if (stepError) {
    console.error(stepError);
    process.exitCode = 1;
  }
  backup.finish(finishError => {
    db.close(closeError => {
      const error = stepError || finishError || closeError;
      if (error) {
        console.error(error);
        process.exitCode = 1;
      } else {
        console.log(destination);
      }
    });
  });
});
