'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const { IS_PRODUCTION, SESSION_SECRET, TRUSTED_PROXIES, PUBLIC_FRONTEND_MODE } = require('./config/env');
const { securityHeaders } = require('./middlewares/security');
const { observeRequestRisk } = require('./middlewares/rateLimit');
const { acceptTrustedFrontendProxy } = require('./middlewares/frontendProxy');
const { publicRouter, adminRouter } = require('./routes');
const PublicController = require('./controllers/PublicController');
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

// 单体模式先暂存 SID/Referer；分离模式由可信边缘入口完成同一流程，API 域名不处理公开落地页。
if (PUBLIC_FRONTEND_MODE === 'embedded') app.use(PublicController.preVerifyInflowTraffic);
app.use(observeRequestRisk);

// 必须早于原后台路由挂载，否则 /api/admin 的统一鉴权会拦截一次性 SSO 票据兑换。
app.use('/api/admin/control-center', ControlCenterAgentService.router);
app.use(publicRouter);
app.use(adminRouter);
app.use('/admin', express.static(path.join(publicDirectory, 'admin')));
if (PUBLIC_FRONTEND_MODE === 'embedded') {
  app.use('/', PublicController.trackSitePageView, PublicController.trackInflow, express.static(publicDirectory));
} else {
  // 分离模式仍暂时提供管理员上传的 Logo；公共 HTML/CSS/JS 不再由 API 服务下发。
  app.use('/uploads/logo', express.static(path.join(publicDirectory, 'uploads', 'logo'), {
    fallthrough: false,
    index: false
  }));
}
app.use((req, res) => fail(res, '接口不存在', 404));

module.exports = app;
