# 机器人风险中心与导航站接入

## 架构边界

- 独立风险中心：接收匿名风险事件、累计评分、发布短期决定；不保存友链、积分、广告或管理员数据。
- 导航站：保留访客 Cookie、SID 归属、读令牌、并发限制和本地挑战；请求路径不等待风险中心。
- 公共前端 Worker：拦截已知 AI/搜索爬虫并提供静默校验静态资源；只有风险中心明确要求挑战时，数据接口才引导访客进入校验页。
- CrowdSec：读取反向代理访问日志，承担网络扫描、恶意 IP 和重复攻击检测；不凭单一 IP 永久处罚共享网络访客。

## 上线顺序

1. 在独立主机启动 `bot-risk-center/docker-compose.yml` 中的 PostgreSQL、Redis、CrowdSec。
2. 执行 `bot-risk-center/migrations/001_initial.sql`，配置独立 HMAC 客户端密钥。
3. 启动风险中心并验证 `/healthz`、HMAC 防重放和决定增量接口。
4. 在导航站配置 `BOT_RISK_CENTER_*`，先使用 `BOT_GATE_MODE=observe` 运行至少 7 天。
5. 检查正常 PC、iOS、安卓、鸿蒙及常见中国大陆浏览器的误报率和挑战耗时。
6. 为 Node.js 与公共前端 Worker 配置相同的独立 `EDGE_ACCESS_SECRET`。
7. 先在测试前台域名切换 `BOT_GATE_MODE=enforce`，验收首页、详情页、SID、3 秒心跳、积分、出站与发布页。
8. 通过后再逐步切换正式前台；保留把模式改回 `observe` 的一键回滚能力。

## 环境变量

```text
BOT_GATE_MODE=off|observe|enforce
BOT_RISK_CENTER_ENABLED=1
BOT_RISK_CENTER_URL=https://risk.example.com
BOT_RISK_ALLOW_PRIVATE_HTTP=0
BOT_RISK_CLIENT_ID=nav-main
BOT_RISK_CLIENT_SECRET=<独立 HMAC 密钥，至少 32 字符>
BOT_RISK_SITE_KEY=webring-main
BOT_RISK_TIMEOUT_MS=800
BOT_RISK_SYNC_INTERVAL_MS=15000
EDGE_ACCESS_SECRET=<仅用于浏览器通行证，至少 32 字符>
BROWSER_ACCESS_TTL_MS=14400000
```

若导航站与风险中心位于同一受控 VPC，可将风险中心绑定到明确的 RFC1918 私网地址，
并在导航站显式设置 `BOT_RISK_ALLOW_PRIVATE_HTTP=1`。该开关不接受公网 IP，HMAC 鉴权仍然必须启用。

## 验收标准

- 已知搜索蜘蛛、AI 爬虫和常见脚本 UA 在边缘得到极简 404/拒绝响应。
- 无风险浏览器直接放行；可疑浏览器才在 Web Worker 中完成静默校验，不出现图片验证码或第三方 Turnstile。
- 通行证只绑定匿名访客和 User-Agent，不绑定公网 IP，NAT、移动网络切换不会连坐。
- 风险中心超时或离线时，已缓存决定和导航站原有保护继续运行；业务请求不等待远端评分。
- 直接访问 `/api/links`、`/api/showcase` 仍须短期读取令牌；单访客读取并发仍不超过 2。
- `BOT_GATE_MODE=off` 时与改造前行为一致；紧急回滚只需切回 `observe` 或 `off` 并重新部署 Worker。

## 暂不自动启用的组件

- Coraza/open-appsec：与 Cloudflare/Caddy 现有规则重叠，先由 CrowdSec 和边缘规则收集数据，再决定是否引入。
- JA4-NGINX：当前 TLS 在 Cloudflare 终止，源站无法获得真实 ClientHello；不为此替换现有代理链。
- CreepJS/FingerprintJS 完整指纹：采集面广、移动端稳定性和隐私成本较高；当前仅采用 BotD 与低成本标准信号。
- Anubis/mCaptcha：本项目已有本地 Web Worker PoW，不再叠加第二套挑战页面。
