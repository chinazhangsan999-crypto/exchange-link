'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const {
  IS_PRODUCTION,
  SESSION_SECRET,
  TRUSTED_PROXIES
} = require('./config/env');
const { securityHeaders } = require('./middlewares/security');
const { observeRequestRisk } = require('./middlewares/rateLimit');
const { acceptTrustedFrontendProxy } = require('./middlewares/frontendProxy');
const { requireAdminFrontendBoundary } = require('./middlewares/adminBoundary');
const { publicRouter, adminRouter } = require('./routes');
const setupRouter = require('./routes/setup');
const ControlCenterAgentService = require('./services/ControlCenterAgentService');
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
app.use(express.json({
  limit: '64kb',
  verify(req, res, buffer) {
    req.rawBody = Buffer.from(buffer);
  }
}));
// 缺少代理头时保持原同源模式；只有携带完整代理上下文时才执行严格验签。
app.use(acceptTrustedFrontendProxy);
// 后台域名可由首次建站向导写入；生产环境未配置时也会默认拒绝直连后台路径。
app.use(requireAdminFrontendBoundary);
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

app.use(observeRequestRisk);
// 仅在尚未保存中央 Cloudflare 配置时开放的一次性初始化入口；成功后自动返回 404。
app.use(setupRouter);

// 必须早于原后台路由挂载，否则 /api/admin 的统一鉴权会拦截一次性 SSO 票据兑换。
app.use('/api/admin/control-center', ControlCenterAgentService.router);
app.use(publicRouter);
app.use(adminRouter);
app.use('/admin', express.static(path.join(publicDirectory, 'admin')));
// 公共前端由独立边缘 Worker 托管；API 服务只保留管理员上传的 Logo。
app.use('/uploads/logo', express.static(path.join(publicDirectory, 'uploads', 'logo'), {
  fallthrough: false,
  index: false,
  dotfiles: 'deny'
}));
app.use((req, res) => fail(res, 'Not Found', 404));

module.exports = app;
