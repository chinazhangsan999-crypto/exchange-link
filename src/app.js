'use strict';

const express = require('express');
const path = require('path');
const session = require('express-session');
const { IS_PRODUCTION, SESSION_SECRET, TRUSTED_PROXIES } = require('./config/env');
const { securityHeaders } = require('./middlewares/security');
const { guestVerificationGate } = require('./middlewares/rateLimit');
const { publicRouter, adminRouter } = require('./routes');
const PublicController = require('./controllers/PublicController');
const { fail } = require('./utils/http');

const app = express();
// app.js 位于 src，静态目录必须上退一级回到项目根目录的 public。
const publicDirectory = path.join(__dirname, '..', 'public');

// 只有显式配置的反向代理才允许影响 Express 的 req.ip。
app.set('trust proxy', TRUSTED_PROXIES.length ? TRUSTED_PROXIES : false);
app.use(securityHeaders);
app.use(express.json({ limit: '64kb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  // 无状态请求不创建空 Session，避免默认 MemoryStore 被扫描流量持续撑大。
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 60 * 1000,
    sameSite: 'lax',
    httpOnly: true,
    secure: IS_PRODUCTION
  }
}));

// 顺序不可交换：这里只在滑块前暂存外部 Referer；任何流量计分必须等到 3 秒心跳。
app.use(PublicController.preVerifyInflowTraffic);
app.use(guestVerificationGate);

app.use(publicRouter);
app.use(adminRouter);
app.use('/admin', express.static(path.join(publicDirectory, 'admin')));
app.use('/', PublicController.trackInflow, express.static(publicDirectory));
app.use((req, res) => fail(res, '接口不存在', 404));

module.exports = app;
