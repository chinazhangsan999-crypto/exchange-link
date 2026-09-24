'use strict';

const path = require('path');

const PROJECT_ROOT = path.resolve(__dirname, '..', '..');
const DATABASE_PATH = path.resolve(process.env.DB_PATH || path.join(PROJECT_ROOT, 'webring.db'));

module.exports = { DATABASE_PATH, PROJECT_ROOT };
