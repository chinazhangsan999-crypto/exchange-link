# 星环导航站（Webring Navigation）

[English documentation](README.en.md)

星环导航站是一个面向多站点的友链、流量交换、广告、反机器人、风险决策和灾难恢复系统。本仓库是导航站运行源代码；风险中心虽然在本仓库中保留了一个可共同开发的目录，但生产上按独立服务部署。

> 本文按当前源码编写。所有域名、账号、Token、数据库密码和 HMAC 密钥均为占位符；真实值只能保存在服务器环境文件或后台加密凭据库中，禁止提交到 Git。

## 1. 系统能力

### 1.1 导航、友链与流量

- 站点、分类、标签、排序、展示卡片和详情页管理。
- 友链申请、审核、反向链接检查、存活检查、Ping、到站/出站统计和流量矩阵。
- 访问入口 `/go`、公开站点 API、精选展示 API、分析与引流事件。
- 本地 SQLite 数据库，支持备份、审计和后台导出。

### 1.2 广告与发布

- 本地广告与控制中心下发广告并存。
- 图片广告、代码广告、位置策略和投放状态。
- 代码广告可通过独立广告 Edge 隔离加载；可用环境变量紧急关闭公开、直连或沙箱代码广告。
- Cloudflare 公共前台 Worker、API Edge、后台 Edge 和广告 Edge 分离，避免直接公开源站管理接口。

### 1.3 访问控制与风险

- 管理员 Session、CSRF、独立 Admin/Guest JWT 密钥。
- 浏览器访问门禁：`off`、`observe`、`enforce` 三种模式。
- Proof-of-Work、浏览器读取令牌、BotD、WebDriver 和搜索引擎爬虫验证。
- 异步上报风险中心，读取人工规则/策略决策，并缓存短期决定。
- 可信反向代理与真实访客 IP 处理；Cloudflare 代理时必须正确限制来源并更新可信代理网段。

### 1.4 灾难恢复

- 生成加密恢复清单和自包含恢复页面，可由 Service Worker 缓存。
- 使用 DNS TXT 发布 A、B、R1 分片；支持发布、回读、版本确认、回滚和审计。
- 三层 DoH 查询线路与自动配置，单次线路上限为 128。
- 支持 Cloudflare DNS、deSEC、ClouDNS、Route 53、DNSPod、AliDNS、百度智能云 DNS、火山引擎 DNS；Hurricane Electric 为手工发布。

### 1.5 外部系统

- 控制中心：站点登记、心跳、配置快照、广告同步和一次性 SSO。
- 风险中心：事件上报、人工决策和策略同步。
- IP 情报：HMAC 签名查询、代理/VPN/云厂商/ASN/地理等证据。
- Telegram 数据库备份；告警以 Telegram 为主，Bark 只在 Telegram 最终失败时兜底。

## 2. 推荐生产拓扑

本项目的完整四系统部署使用两台服务器：

| 服务器 | 服务 | 监听地址 | 公网入口 |
|---|---|---|---|
| A | 导航站 | `127.0.0.1:3001` | `nav.example.com`、`admin.example.com`、API/Worker 域名 |
| A | 风险中心 | `127.0.0.1:4100` | `risk.example.com` |
| B | 控制中心 | `127.0.0.1:3100` | `control.example.com` |
| B | IP 情报 | `127.0.0.1:3101` | `ip.example.com` |

两台服务器只开放 SSH、HTTP 和 HTTPS。PostgreSQL、Redis 和四个 Node 端口不对公网开放。跨服务器内部接入由管理员在各后台配置；本 README 不自动写入系统间密钥。

## 3. 运行要求

- Ubuntu 22.04/24.04 LTS，建议 2 vCPU、4 GiB RAM、30 GiB SSD 起。
- Node.js 22 LTS（本项目可运行，且与同机风险中心兼容）。
- Caddy 2、Git、SQLite3、构建工具。
- 风险中心另需 PostgreSQL 16/17 和 Redis 7。
- 四个独立 HTTPS 域名；若使用 Cloudflare 代理，SSL/TLS 模式设为 **Full (strict)**。
- 一个非 root 运行用户；示例为 `apps`。

## 4. 服务器 A：从空服务器安装

以下命令以 Ubuntu 和有 sudo 权限的登录用户为例。

### 4.1 基础软件和运行用户

```bash
sudo apt update
sudo apt install -y ca-certificates curl git build-essential sqlite3 postgresql redis-server
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
sudo useradd --system --create-home --home-dir /opt/apps --shell /usr/sbin/nologin apps
sudo mkdir -p /opt/webring-navigation /etc/webring-navigation /var/lib/webring-navigation
sudo chown -R apps:apps /opt/webring-navigation /var/lib/webring-navigation
sudo chmod 750 /etc/webring-navigation
```

安装 Caddy 时应使用其官方 Debian/Ubuntu 仓库；安装后先不要公开尚未配置的源站。

### 4.2 获取代码

推荐为服务器创建只读 GitHub Deploy Key（仓库权限仅 `Contents: Read`），不要把个人 PAT 写入命令历史。

```bash
sudo -u apps git clone https://github.com/zhangsan4188/webring-navigation.git /opt/webring-navigation
cd /opt/webring-navigation
sudo -u apps npm ci --omit=dev
sudo -u apps npm run build:public-frontend
```

如使用镜像仓库，把地址替换为 `https://github.com/chinazhangsan999-crypto/exchange-link.git`。

### 4.3 创建环境文件

先生成互不相同的随机值：

```bash
openssl rand -hex 32   # SESSION_SECRET
openssl rand -hex 32   # ADMIN_JWT_SECRET
openssl rand -hex 32   # GUEST_JWT_SECRET
openssl rand -base64 48 # FRONTEND_PROXY_SECRET
openssl rand -base64 48 # EDGE_ACCESS_SECRET
```

创建 `/etc/webring-navigation/navigation.env`：

```dotenv
NODE_ENV=production
PORT=3001
SESSION_SECRET=<独立随机值>
ADMIN_JWT_SECRET=<独立随机值>
GUEST_JWT_SECRET=<独立随机值>
FRONTEND_PROXY_SECRET=<与 API/Admin Worker 共享的随机值>
EDGE_ACCESS_SECRET=<仅源站使用的独立随机值>
INITIAL_ADMIN_PASSWORD=admin123
ADMIN_FRONTEND_ORIGIN=https://admin.example.com
FRONTEND_PROXY_API_HOSTS=nav.example.com,api.example.com,admin.example.com
TRUSTED_PROXIES=127.0.0.1,::1
BOT_GATE_MODE=off
BOT_RISK_CENTER_ENABLED=0
CONTROL_CENTER_ENABLED=0
IP_INTELLIGENCE_ENABLED=0
TRAFFIC_DEBUG=0
```

```bash
sudo chown root:apps /etc/webring-navigation/navigation.env
sudo chmod 640 /etc/webring-navigation/navigation.env
```

生产环境强制要求 `SESSION_SECRET`、`ADMIN_JWT_SECRET`、`GUEST_JWT_SECRET` 和 `FRONTEND_PROXY_SECRET`。这些值不得相同，且轮换会使现有会话或签名失效。

首次约定账号为 `admin`、密码为 `admin123`。该密码只用于首次引导，不应长期用于公网生产环境；完成登录或控制中心接管后立即在后台修改或关闭本地密码入口。

### 4.4 systemd

创建 `/etc/systemd/system/webring-navigation.service`：

```ini
[Unit]
Description=Webring Navigation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=apps
Group=apps
WorkingDirectory=/opt/webring-navigation
EnvironmentFile=/etc/webring-navigation/navigation.env
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/opt/webring-navigation /var/lib/webring-navigation

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now webring-navigation
sudo systemctl status webring-navigation --no-pager
curl -fsS http://127.0.0.1:3001/api/health
```

SQLite 数据库首次启动自动创建。备份目录必须由 `apps` 写入且权限为 `700`；不要把运行数据库或备份纳入 Git。

### 4.5 Caddy

同机风险中心的 Caddyfile 示例：

```caddyfile
nav.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:3001
}

risk.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:4100
}
```

公共前台和后台采用 Worker 时，源站 Caddy 还应限制为 Cloudflare 来源，并由 Worker 添加共享签名；不要仅依赖可伪造的 `X-Forwarded-For`。若 Cloudflare 橙云开启，DNS 指向服务器 A，源站证书/ACME 必须能完成验证；Full (strict) 不接受无效源站证书。

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
curl -fsS https://nav.example.com/api/health
```

## 5. 首次后台配置顺序

1. 使用 `admin/admin123` 登录后台并立即更改引导密码。
2. 配置公共前台 Worker、API Edge 和 Admin Edge；核对 Worker secrets 与源站一致。
3. 添加允许的前台 Origin，禁止通配符。
4. 先把门禁设为 `observe`，验证数据正常后再切换 `enforce`。
5. 在控制中心创建站点并取得站点凭据，再在导航后台验证保存。
6. 在风险中心创建 Client ID/Secret，再在导航后台选择观察或执行模式并验证保存。
7. 在 IP 系统创建独立 Client ID/Secret，再在导航后台验证保存。
8. 配置 DNS 恢复通道、A/B/R1 记录和三层查询线路；发布后必须执行 DoH 回读。
9. 配置 Telegram 备份和告警；单独测试 Telegram、Bark 兜底和备份机器人。

## 6. 第三方账号、字段和最小权限

### 6.1 Cloudflare（前台、Edge 和 DNS）

需要：Account ID、Zone、API Token、Worker/路由名称和域名。

最小权限按实际功能拆分 Token，避免一个全局 Token：

- Worker 部署：Account `Workers Scripts: Edit`；对应 Zone `Workers Routes: Edit`、`Zone: Read`。
- 自动创建/修改 DNS：对应 Zone `DNS: Edit`；只检查记录可改为 `DNS: Read`。
- 控制中心部署 Cloudflare Pages 时使用另一枚 Token：Account `Cloudflare Pages: Edit`，Zone `Zone: Read`、`DNS: Edit`。
- 资源范围只选择指定 Account 和指定 Zone；不要选 All accounts/All zones。

`FRONTEND_PROXY_SECRET` 是 Worker 与导航源站共享的应用密钥，不是 Cloudflare Token；`EDGE_ACCESS_SECRET` 只保存在源站。

### 6.2 DNS 恢复服务商

| 服务商 | 后台字段 | 最小权限/动作 | 注意事项 |
|---|---|---|---|
| Cloudflare DNS | Account ID、API Token | `Zone: Read`、`DNS: Edit`，限定 Zone | 只用于 TXT 恢复记录时不要授予 Worker 权限 |
| deSEC | Token | 对指定 zone 的读取和写入 RRset | 使用专用 Token；限制可操作域 |
| ClouDNS | Auth ID / Sub-auth ID、Auth Password | Zone/record 列表、创建、删除 | HTTP API 可能需要付费套餐；“没有 HTTP API”是套餐限制，不是代码错误 |
| AWS Route 53 | Access Key ID、Secret Access Key；临时凭据另填 Session Token | `route53:ListHostedZonesByName`、`route53:ListResourceRecordSets`、`route53:ChangeResourceRecordSets` | IAM 限定 Hosted Zone、TXT 类型和 `_recovery*` 名称；优先短期 STS 凭据 |
| 腾讯云 DNSPod | SecretId、SecretKey | `DescribeDomainList`、`DescribeRecordList`、`CreateRecord`、`DeleteRecord` | CAM 自定义策略只授权目标域名；不要使用主账号永久密钥 |
| 阿里云 AliDNS | AccessKey ID、AccessKey Secret | `DescribeDomains`、`DescribeDomainRecords`、`AddDomainRecord`、`DeleteDomainRecord` | 使用 RAM 用户/角色并限制 domain ARN |
| 百度智能云 DNS | Access Key ID、Secret Access Key | Zone/record 列表、创建、删除 | 使用子用户自定义策略，限制目标 zone |
| 火山引擎 DNS | Access Key、Secret Key、Region；临时凭据另填 Session Token | `ListZones`、`ListRecords`、`CreateRecord`、`DeleteRecord` | 使用 IAM 子用户并限制 DNS 资源 |
| Hurricane Electric | 无自动凭据 | 手工发布 | 当前源码不自动写入，后台只保存发布说明 |

TXT 权限必须允许读取、创建和删除，因为系统需要发布新 generation、回读校验并清理旧分片。不要授予域名注册、转移、账单或账户管理权限。

### 6.3 Telegram、Bark 和 Webhook

- 告警 Bot：Bot Token、Chat ID；机器人必须能向目标私聊/群组/频道发送消息。
- 备份 Bot：使用不同 Bot Token 和 Chat ID；只允许发送到专用备份会话。
- Bark：服务器地址与 Device Key；它只在 Telegram 重试后最终失败时使用。
- Webhook：若启用，使用独立 HTTPS Endpoint 和随机签名密钥。

机器人加入群组或频道后授予“发送消息”即可，不应授予删除消息、添加管理员等无关权限。备份中包含加密数据，解密密钥必须与分片分开保存。

### 6.4 控制中心、风险中心和 IP 系统

这些不是第三方 Token，必须分别生成，禁止复用：

- 控制中心站点凭据：由控制中心创建站点或轮换时一次性显示。
- 风险中心 Client ID/Secret：Secret 至少 32 字符，站点标识与风险中心登记一致。
- IP 情报 Client ID/Secret：由 IP 系统 `client:admin` 生成；每个导航站独立一对。

同机风险中心可使用 `http://127.0.0.1:4100`；跨服务器连接必须使用 HTTPS。关闭集成只停止后续同步，不会自动删除对方已有数据。

## 7. 环境变量说明

| 变量 | 必需 | 说明 |
|---|---|---|
| `SESSION_SECRET` | 生产必需 | Session 签名 |
| `ADMIN_JWT_SECRET` | 生产必需 | 管理员令牌签名 |
| `GUEST_JWT_SECRET` | 生产必需 | 访客/验证令牌签名 |
| `FRONTEND_PROXY_SECRET` | 生产必需 | Edge 到源站的请求签名，至少 32 字符 |
| `ADMIN_FRONTEND_ORIGIN` | 推荐 | 唯一可信后台 Origin |
| `FRONTEND_PROXY_API_HOSTS` | 推荐 | 允许进入源站代理的主机名列表 |
| `INITIAL_ADMIN_PASSWORD` | 首次部署 | 引导密码，至少 8 位；生产建议 12 位以上 |
| `TRUSTED_PROXIES` | 按拓扑 | 只填实际代理地址/网段 |
| `BOT_GATE_MODE` | 可选 | `off` / `observe` / `enforce` |
| `BOT_RISK_*` | 启用风险中心时 | URL、Client ID、Secret、Site Key、超时和同步间隔 |
| `CONTROL_CENTER_*` | 启用控制中心时 | URL、站点凭据或 0600 凭据文件 |
| `IP_INTELLIGENCE_*` | 启用 IP 时 | Base URL、Client ID、Secret 或凭据文件 |
| `PUBLIC_CODE_ADS_ENABLED` | 可选 | 代码广告总开关 |
| `DIRECT_CODE_ADS_ENABLED` | 可选 | 直连代码广告开关 |
| `SANDBOX_CODE_ADS_ENABLED` | 可选 | 沙箱代码广告开关 |

## 8. 更新、验证和回滚

更新前备份 SQLite、环境文件和服务器凭据目录；密钥备份不得进入代码包。

```bash
sudo systemctl stop webring-navigation
sudo -u apps cp -a /opt/webring-navigation/data /var/lib/webring-navigation/backup-$(date +%Y%m%d-%H%M%S)
cd /opt/webring-navigation
sudo -u apps git fetch --all --prune
sudo -u apps git pull --ff-only
sudo -u apps npm ci --omit=dev
sudo -u apps npm run build:public-frontend
sudo systemctl start webring-navigation
curl -fsS http://127.0.0.1:3001/api/health
```

仓库没有统一 `npm test` 脚本时，不要把“无测试脚本”当成通过；应运行 `node --test` 指定现有测试文件，并至少执行：

```bash
node --check server.js
git diff --check
```

回滚应恢复已验证的 Git commit 与同一时点数据库备份。只回滚代码、不回滚不兼容数据库可能导致启动失败；反之亦然。

## 9. 上线验收

- `systemctl is-active webring-navigation` 返回 `active`。
- 本机 `/api/health` 与公网健康地址均返回 200。
- 后台登录、CSRF、退出、改密可用，源站 IP 不能绕过后台 Edge。
- 新建测试友链后，申请、审核、详情、跳转和统计闭环正常。
- 风险中心/IP/控制中心均通过“测试连接”，且 Client ID 与站点标识一致。
- 恢复 TXT 发布、三层 DoH 回读、离线恢复页、A/B/R1 版本确认均通过。
- Telegram 测试成功；模拟 Telegram 失败时 Bark 才触发。
- SQLite、凭据目录和备份权限符合预期，无 Token 出现在日志、HTML、Git 或进程参数中。

## 10. 故障排查

- **后台 404**：检查 Admin Worker 路由、`ADMIN_FRONTEND_ORIGIN`、允许 Origin 和 API Edge Host，而不是先放宽源站。
- **风险中心凭据失败**：Client ID 必须完全匹配；Secret 是一次性明文，重新生成后旧值立即失效。
- **DNS 显示已写入但未回读**：核对权威 NS、代理商 zone、TXT 分片完整性、TTL 和三层 DoH 传播；不要把“已提交 API”视为“全球已生效”。
- **ClouDNS `You don't have access to the HTTP API`**：检查套餐是否包含 HTTP API。
- **恢复页一直读取清单**：确认 Service Worker 缓存属于当前 Origin、恢复 TXT generation 完整且至少一个查询层成功；旧缓存可在 DevTools Application 中注销 Service Worker 后重测。
- **真实 IP 全相同或可伪造**：只信任实际反向代理；Caddy/Cloudflare 应覆盖而不是追加访客可控头。

## 11. 安全底线

- 不提交 `.env`、数据库、备份、Worker secrets、Token、Client Secret 或 OAuth refresh token。
- 每个系统、站点、用途使用独立密钥；禁用离职人员和废弃服务器的凭据。
- 后台与 API 只通过 HTTPS；数据库/Redis 只监听回环或私网。
- Token 使用最小权限和最小资源范围，并设置到期时间与轮换记录。
- 日志只记录凭据指纹或“已配置”，不回显明文。
- 正式执行模式前先观察；规则变更、DNS 发布和密钥轮换必须保留审计和回滚点。

## 12. 许可与上游条款

本仓库自身许可与第三方依赖/数据许可相互独立。DNS、Cloudflare、Telegram、Bark、数据库和恢复数据的使用必须遵守各服务商条款；公开分发恢复数据前还应检查其中是否含有受限制的数据或内部地址。

官方权限参考：[Cloudflare API Token 权限](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)、[Route 53 服务授权动作](https://docs.aws.amazon.com/service-authorization/latest/reference/list_route53.html)、[Route 53 精细记录权限](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-permissions.html)。
