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
  const status = Number(error?.statusCode) >= 400 && Number(error?.statusCode) < 600 ? Number(error.statusCode) : 500;
  return res.status(status).json({ code: status, message: status === 500 ? 'Internal Server Error' : error.message });
});

module.exports = app;
