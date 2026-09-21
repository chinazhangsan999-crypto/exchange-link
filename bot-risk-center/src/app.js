'use strict';

const express = require('express');
const router = require('./routes');

const app = express();
app.disable('x-powered-by');
app.use(express.json({
  limit: '128kb',
  verify(req, res, buffer) { req.rawBody = Buffer.from(buffer); }
}));
app.use(router);
app.use((req, res) => res.status(404).json({ code: 404, message: 'Not Found' }));
app.use((error, req, res, next) => {
  console.error(error?.stack || error);
  if (res.headersSent) return next(error);
  return res.status(500).json({ code: 500, message: 'Internal Server Error' });
});

module.exports = app;
