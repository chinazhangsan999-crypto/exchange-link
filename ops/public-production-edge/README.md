# 正式公共前端 Worker

此 Worker 在 `qiantai.chinazhangsan.ccwu.cc` 提供纯静态前台，并将公共 API、入站落地和 `/go` 以签名方式转发给数据域名。

部署前：

1. 执行 `npm run build:public-frontend`。
2. 复制 `wrangler.toml.example` 为本地 `wrangler.toml`。
3. 使用与 Node.js、API Worker 一致的 `FRONTEND_PROXY_SECRET` 执行 `wrangler secret put`。
4. `npx wrangler deploy --config ops/public-production-edge/wrangler.toml`。

Node.js 已永久关闭公共静态托管；部署后必须验收首页、详情、SID 落地、心跳和出站跳转。
