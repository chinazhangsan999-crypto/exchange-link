# 广告 Edge Worker

代码广告统一通过独立广告 API 域名加载，不再由导航站 `/api/showcase` 返回代码原文。

- `GET /direct/<ticket>`：向被分配的前台 Origin 返回代码 JSON，导航站校验 SHA-256 后在主页面执行。
- `GET /frame/<ticket>`：在无 `allow-same-origin` 的 sandbox iframe 中执行代码，并通过 `postMessage` 回报高度。
- `GET /health`：部署健康检查。

推荐在总后台“广告管理 → 广告 API 管理”中保存 Cloudflare 账号、域名与分配范围，再点击“部署/更新”。总后台会创建 Worker、写入内部密钥、绑定自定义域名，并把每个导航站的短期票据密钥随配置快照下发。

浏览器会看到广告 API 域名，这是正常且必要的；Cloudflare API Token、总后台内部密钥与广告代码原文不会进入静态前端源码或配置快照。

手工部署仅用于故障恢复。手工方式必须同时配置 `BACKEND_ORIGIN`、`PROFILE_ID` 和 Secret `BACKEND_SECRET`，并保证它们与总后台数据库中的广告 API 配置一致。
