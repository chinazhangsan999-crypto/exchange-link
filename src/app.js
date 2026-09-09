'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const { IS_PRODUCTION, SESSION_SECRET, TRUSTED_PROXIES } = require('./config/env');
const { securityHeaders } = require('./middlewares/security');
const { observeRequestRisk } = require('./middlewares/rateLimit');
const { publicRouter, adminRouter } = require('./routes');
const PublicController = require('./controllers/PublicController');
const { fail } = require('./utils/http');

const app = express();
// app.js 位于 src，静态目录必须上退一级回到项目根目录的 public。
const publicDirectory = path.join(__dirname, '..', 'public');
// Session 与业务 webring.db 分库，避免访客 Session 写入和高频流量日志争抢同一 SQLite 写锁。
const sessionDirectory = path.join(__dirname, '..', 'data');
fs.mkdirSync(sessionDirectory, { recursive: true });
const sessionStore = new SQLiteStore({
  db: 'sessions.sqlite',
  dir: sessionDirectory,
  concurrentDB: true
});

// 只有显式配置的反向代理才允许影响 Express 的 req.ip。
app.set('trust proxy', TRUSTED_PROXIES.length ? TRUSTED_PROXIES : false);
app.use(securityHeaders);
app.use(express.json({ limit: '64kb' }));
app.use(session({
  store: sessionStore,
  name: 'webring.sid',
  secret: SESSION_SECRET,
  resave: false,
  // 无状态请求不创建空 Session，避免默认 MemoryStore 被扫描流量持续撑大。
  saveUninitialized: false,
  unset: 'destroy',
  cookie: {
    maxAge: 30 * 60 * 1000,
    sameSite: 'lax',
    httpOnly: true,
    secure: IS_PRODUCTION
  }
}));

// 顺序不可交换：先暂存 SID/Referer，再观察动态请求风险；首页不会因缺少验证 Cookie 被拦截。
app.use(PublicController.preVerifyInflowTraffic);
app.use(observeRequestRisk);

app.use(publicRouter);
app.use(adminRouter);
app.use('/admin', express.static(path.join(publicDirectory, 'admin')));
app.use('/', PublicController.trackInflow, express.static(publicDirectory));
app.use((req, res) => fail(res, '接口不存在', 404));

module.exports = app;
