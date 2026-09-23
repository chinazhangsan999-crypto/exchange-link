'use strict';

const path = require('node:path');
const sqlite3 = require('sqlite3').verbose();

const databasePath = path.resolve(process.env.DB_PATH || path.join(__dirname, '..', 'webring.db'));
const db = new sqlite3.Database(databasePath);
db.all(`SELECT key,value FROM site_configs
  WHERE key LIKE 'ad_edge_%' OR key IN ('control_center_revision','control_center_site_id')
  ORDER BY key`, (error, rows) => {
  if (error) throw error;
  const safeRows = rows.map(row => ({
    key: row.key,
    value: row.key === 'ad_edge_ticket_key' ? String(row.value || '').length : row.value
  }));
  process.stdout.write(`${JSON.stringify(safeRows)}\n`);
  db.close();
});
