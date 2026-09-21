# 公共前端边缘兼容层

这个 Worker 在公共前端域名上同时完成两件事：提供独立打包后的访客静态文件，并把现有相对路径 API 同源转发到 Node.js API 域名。浏览器仍然只访问公共前端域名，因此现有 Cookie、SID、3 秒心跳、读取凭证、`/go` 出站统计和 Referer 语义无需改写为第三方 Cookie。构建过程会明确排除整个 `public/admin/`，公共托管空间不会携带后台源码。

## 准备配置

1. 执行 `npm run build:public-frontend` 生成不含后台文件的 `dist/public-frontend/`。
2. 复制 `wrangler.toml.example` 为 `wrangler.toml`，将 `API_ORIGIN` 指向独立数据域名（由 `../api-edge/` Worker 提供）。
3. 在 Worker 中保存一个不少于 32 位的随机 `FRONTEND_PROXY_SECRET`；同一密钥只保存在 Worker Secret 与 Node.js 环境变量中。
   浏览器通行证使用独立的 `EDGE_ACCESS_SECRET`，它只保存在 Node.js，不下发到 Worker 或浏览器。
4. 通过后台 API `PUT /api/admin/frontend-origins` 将即将启用的公共前端 Origin 加入白名单。
5. 使用测试域名完成首页、详情页、SID、心跳和出站跳转验收。
6. Node.js 永久只提供 API、内部接口、后台静态页面与上传 Logo，不再下发公共 HTML/CSS/JS。

## 为什么不直接使用跨站 Cookie

纯静态前端直连另一个站点的 API 会依赖第三方 Cookie。Safari、Chrome 隐私模式以及部分中国大陆手机浏览器可能阻止或分区这类 Cookie，进而破坏访客 ID、限流、SID 归属和 3 秒心跳。边缘同源代理让浏览器仍使用第一方 Cookie，同时由 HMAC 签名保护真实客户端 IP 和允许的前端 Origin。

## 后端环境变量

```text
FRONTEND_PROXY_SECRET=<与 Worker Secret 完全一致的随机密钥>
FRONTEND_PROXY_MAX_SKEW_MS=30000
FRONTEND_PROXY_API_HOSTS=<仅当 Node.js 直接承载 API 域名时填写，多个域名以逗号分隔>
BOT_GATE_MODE=off
EDGE_ACCESS_SECRET=<启用 enforce 前配置的独立随机密钥>
BROWSER_ACCESS_TTL_MS=14400000
```

`BOT_GATE_MODE` 按 `off → observe → enforce` 分阶段切换。`off` 不改变访客路径；`observe` 只采集风险事件；`enforce` 才会让未持有浏览器通行证的页面导航进入本地静默校验。不要直接跳过观察期上线强制模式。

公共前端必须经可信边缘签名访问业务 API；Node.js 不再提供可重新开启的单体兼容开关。

推荐链路为：浏览器只访问公共前端域名，公共前端 Worker 签名后请求独立数据域名，数据域名 Worker 再把已签名请求转发给 Node.js。这样 Cookie 始终属于公共前端域名，不依赖容易被浏览器阻止的第三方 Cookie。
