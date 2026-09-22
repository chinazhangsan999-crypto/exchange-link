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

- 管理入口：`https://fengxian.chinazhangsan.ccwu.cc/admin`
- 使用账号和密码登录；默认账号为 `admin`，默认密码为 `admin123`。生产环境可通过 `BOT_RISK_ADMIN_USERNAME` 与 `BOT_RISK_ADMIN_PASSWORD_HASH` 覆盖，服务端只保存 scrypt 哈希。登录成功后改用 HttpOnly、Secure、SameSite=Strict 会话。
- 首次部署后必须立即通过环境变量替换默认管理员密码，严禁在生产环境继续使用默认凭据。
- 后台可实时开启或关闭每个 `site_key` 的风险中心对接。关闭后 `/v1/*` 返回 403，导航站继续独立运行。
- `ops/Caddyfile` 只公开 `/admin*` 与 `/health`；HMAC 数据线路继续使用 Google Cloud 私网地址。

### 风险告警

- 后台“告警设置”可独立启用 Telegram、Bark，并配置聚合阈值与同类告警冷却时间。
- 紧急信号按站点与风险类型聚合，普通疑似按唯一访客计数，避免同一程序重复请求造成通知轰炸。
- Telegram 正文保守限制为 3800 字符且默认至少间隔 1200ms；Bark 标题/正文按 UTF-8 字节安全截断，默认至少间隔 2000ms。
- Bot Token 与 Bark Device Key 使用 `BOT_RISK_CREDENTIAL_KEY` 加密入库，管理接口只返回“是否已配置”，不会回显明文。
- 可选启用上游版本更新提醒；通知仍经过相同的 Telegram/Bark 字符截断、串行队列和发送间隔。

### 组件更新与只读维护接口

- 后台“组件更新”跟踪 CrowdSec、BotD 及参考项目的最新 Release/Tag、检查时间和人工跟进状态，不会自动安装生产版本。
- 管理员可生成 15 分钟、最多 50 次读取的临时 Bearer Token；数据库只保存 Token 的 SHA-256 摘要。
- `GET /v1/maintenance/snapshot` 返回服务、数据库、Redis、汇总指标与上游版本的脱敏快照。
- `GET /v1/maintenance/upstreams` 仅返回上游项目版本与跟进状态，不包含环境变量、凭据或访客明细。
- 可选设置 `BOT_RISK_GITHUB_TOKEN` 提高 GitHub API 额度；该 Token 只保存在服务器环境变量中。

### 导航站运行清单

- 导航站继续复用原有 HMAC、时间戳和一次性 Nonce，不创建第二套维护密钥。
- `POST /v1/agent/inventory` 接收应用版本、Git 提交、Node 版本、协议版本、组件版本和静态资源 SHA-256；禁止上传环境变量、访客数据及任何密钥。
- `GET /v1/agent/advisories` 只返回当前 `site_key` 的更新建议，不能读取其他站点。
- `POST /v1/agent/test-results` 保存目标版本、浏览器矩阵、误判变化和测试结论。
- 导航站启动约 5 秒后首次上报，以后每 6 小时上报并拉取一次本站建议；该任务不在访客请求链路中。
- 后台“组件更新”中的站点运行版本矩阵会标记超过 12 小时未上报的清单。
- 客户端权限分为 `risk.events.write`、`risk.decisions.read`、`risk.policy.read`、`maintenance.inventory.write`、`maintenance.advisory.read`、`maintenance.test-result.write`，不包含管理员或远程执行权限。

## 决策边界

- 已知 AI/搜索机器人可直接 `deny`。
- 单一 BotD、IP、Referer 或 Fetch Metadata 信号不得直接封禁。
- 导航站请求路径不得同步依赖本服务；事件异步上报，决定在导航站本地缓存。
- 本服务故障时，导航站继续使用 Cloudflare、浏览器门禁、读取 Token、并发限制和本地 PoW。
