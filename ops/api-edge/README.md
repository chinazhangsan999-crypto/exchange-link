# 独立数据域名边缘网关

该 Worker 绑定独立 API 自定义域名，只允许健康检查直接访问。其余数据接口必须携带公共前端 Worker 生成的完整 HMAC 上下文，验签通过后才转发到 Node.js Origin。

部署步骤：

1. 复制 `wrangler.toml.example` 为 `wrangler.toml` 并填写 API 自定义域名、专用回源域名和允许的公共前端 Origin。专用回源域名不得与公开前台或 API Worker 域名复用。
2. 使用与公共前端 Worker、Node.js 相同的 `FRONTEND_PROXY_SECRET` 执行 `wrangler secret put FRONTEND_PROXY_SECRET`。
3. 执行 `wrangler deploy`。Cloudflare Custom Domain 会自动创建 DNS 与证书。
4. 验证 `/api/health` 返回 200，而无签名的 `/api/links`、`/admin` 和 `/` 均返回 404。
5. 将公共前端 Worker 的 `API_ORIGIN` 改为该独立数据域名，再重新部署并验证完整统计链路。
