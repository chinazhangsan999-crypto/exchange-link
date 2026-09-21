# 机器人风险中心

该服务只负责风险事件、策略和决定，不保存友链、广告、积分或导航站管理员数据。

## 本地启动

1. 从 `.env.example` 创建运行环境变量，生成至少 32 字符的独立密钥。
2. 启动 PostgreSQL、Redis 和 CrowdSec。
3. 执行 `migrations/001_initial.sql`。
4. 安装依赖并运行 `npm start`。

若宿主机的 `127.0.0.1:5432` 已被其他 PostgreSQL 使用，可在 Compose 环境文件中设置
`POSTGRES_BIND_PORT`，并让 `DATABASE_URL` 指向同一个本机端口；容器内部端口保持 5432。

生产环境仅监听回环或 RFC1918 私网地址，由受信反向代理提供 TLS。导航站通过 HMAC 调用 `/v1/*`；健康检查不返回版本、配置或依赖细节。

## 管理后台

- 管理入口：`https://fengxian.changzhangsan.ccwu.cc/admin`
- 使用账号和密码登录；默认账号为 `admin`，默认密码为 `admin123`。生产环境可通过 `BOT_RISK_ADMIN_USERNAME` 与 `BOT_RISK_ADMIN_PASSWORD_HASH` 覆盖，服务端只保存 scrypt 哈希。登录成功后改用 HttpOnly、Secure、SameSite=Strict 会话。
- 后台可实时开启或关闭每个 `site_key` 的风险中心对接。关闭后 `/v1/*` 返回 403，导航站继续独立运行。
- `ops/Caddyfile` 只公开 `/admin*` 与 `/health`；HMAC 数据线路继续使用 Google Cloud 私网地址。

## 决策边界

- 已知 AI/搜索机器人可直接 `deny`。
- 单一 BotD、IP、Referer 或 Fetch Metadata 信号不得直接封禁。
- 导航站请求路径不得同步依赖本服务；事件异步上报，决定在导航站本地缓存。
- 本服务故障时，导航站继续使用 Cloudflare、浏览器门禁、读取 Token、并发限制和本地 PoW。
