# 机器人风险中心（Bot Risk Center）

[English documentation](README.en.md)

风险中心是独立的机器人行为分析、规则决策、人工处置、告警和维护情报服务。它接收导航站上报的风险事件，集中生成观察或执行决定；不会替代导航站自身的浏览器门禁。

> 真实密钥只保存在服务器 `.env` 或后台加密库中。README 中的值均为占位符。

## 1. 功能总览

- HMAC 客户端鉴权、事件上报、策略读取和决定读取。
- 站点、Client ID/Secret、接入状态和凭据轮换。
- 疑似访客、证据时间线、信号聚合、人工允许/阻止/观察处置。
- 人工规则、策略修订、预览、启停、审计和 Telegram 加密备份。
- 规则信号包括已知 AI 爬虫、令牌重放、扫描、并发、BotD、WebDriver 和验证失败等。
- PostgreSQL 持久化、Redis 短期状态/缓存、保留期清理。
- Telegram 主告警；仅当 Telegram 最终失败时使用 Bark。
- 独立 Backup Bot 将 AES-256-GCM 加密的规则备份分片发送到专用会话。
- Google Drive 维护备份、GitHub/npm 上游版本检查、维护项目与站点测试。
- 可选 CrowdSec LAPI 集成；服务自身保持私网监听。

## 2. 部署位置

风险中心与导航站部署在服务器 A：

- 导航站：`127.0.0.1:3001`
- 风险中心：`127.0.0.1:4100`
- PostgreSQL：`127.0.0.1:5432`
- Redis：`127.0.0.1:6379`
- Caddy：公网 80/443，`risk.example.com` 反代 4100

同机导航站使用 `http://127.0.0.1:4100` 可避免公网往返；公网后台仍使用 HTTPS。不要把 4100、5432 或 6379 暴露到互联网。

## 3. 从空服务器安装

服务器 A 的 Node.js、Caddy 和 `apps` 用户可与导航站共用。

### 3.1 PostgreSQL 和 Redis

```bash
sudo apt update
sudo apt install -y postgresql redis-server git build-essential
sudo systemctl enable --now postgresql redis-server
sudo -u postgres psql <<'SQL'
CREATE USER botrisk WITH ENCRYPTED PASSWORD 'REPLACE_WITH_RANDOM_DATABASE_PASSWORD';
CREATE DATABASE botrisk OWNER botrisk;
REVOKE ALL ON DATABASE botrisk FROM PUBLIC;
SQL
sudo mkdir -p /opt/bot-risk-center /etc/bot-risk-center
sudo chown -R apps:apps /opt/bot-risk-center
sudo chmod 750 /etc/bot-risk-center
```

数据库必须是新空库；应用首次启动会依次执行仓库中的迁移。数据库密码请先用 `openssl rand -base64 36` 生成并替换，切勿照抄占位符。

### 3.2 获取代码

```bash
sudo -u apps git clone https://github.com/zhangsan4188/bot-risk-center.git /opt/bot-risk-center
cd /opt/bot-risk-center
sudo -u apps npm ci --omit=dev
```

镜像仓库为 `https://github.com/chinazhangsan999-crypto/bot-risk-center.git`。使用只读 Deploy Key 时只需 `Contents: Read`。

### 3.3 生成管理员哈希和应用密钥

约定的首次账号为 `admin`、首次密码为 `admin123`，必须在首次登录后立即改为至少 12 位的唯一强密码。用以下命令生成兼容的 `scrypt` 哈希；命令只在终端本地处理密码：

```bash
node -e "const c=require('node:crypto');const p=process.argv[1];const s=c.randomBytes(16).toString('hex');c.scrypt(p,s,64,(e,d)=>{if(e)throw e;console.log('scrypt$'+s+'$'+d.toString('hex'))})" 'admin123'
openssl rand -base64 48  # BOT_RISK_CREDENTIAL_KEY
openssl rand -base64 48  # navigation client secret
```

### 3.4 环境文件

创建 `/etc/bot-risk-center/risk.env`：

```dotenv
NODE_ENV=production
PORT=4100
RISK_LISTEN_HOST=127.0.0.1
DATABASE_URL=postgres://botrisk:<数据库密码>@127.0.0.1:5432/botrisk
REDIS_URL=redis://127.0.0.1:6379
BOT_RISK_ADMIN_USERNAME=admin
BOT_RISK_ADMIN_PASSWORD_HASH=<上一步的完整 scrypt 值>
BOT_RISK_CREDENTIAL_KEY=<至少 32 字符且长期保留>
BOT_RISK_INTERNAL_URL=http://127.0.0.1:4100
BOT_RISK_PUBLIC_URL=https://risk.example.com
BOT_RISK_CLIENTS_JSON={"nav-main":"<至少 32 字符的导航站专用密钥>"}
EVENT_RETENTION_DAYS=7
CROWDSEC_LAPI_URL=
CROWDSEC_LAPI_KEY=
BOT_RISK_GITHUB_TOKEN=
```

```bash
sudo chown root:apps /etc/bot-risk-center/risk.env
sudo chmod 640 /etc/bot-risk-center/risk.env
```

`BOT_RISK_CREDENTIAL_KEY` 用于加密后台保存的第三方凭据；丢失后不能恢复已加密数据。每个导航站必须使用不同 Client ID/Secret，不能复制同一 Secret 给多个站点。

### 3.5 systemd

创建 `/etc/systemd/system/bot-risk-center.service`：

```ini
[Unit]
Description=Bot Risk Center
After=network-online.target postgresql.service redis-server.service
Wants=network-online.target

[Service]
Type=simple
User=apps
Group=apps
WorkingDirectory=/opt/bot-risk-center
EnvironmentFile=/etc/bot-risk-center/risk.env
ExecStart=/usr/bin/node src/server.js
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/opt/bot-risk-center

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bot-risk-center
sudo systemctl status bot-risk-center --no-pager
curl -fsS http://127.0.0.1:4100/health
curl -fsS http://127.0.0.1:4100/ready
```

### 3.6 Caddy

在服务器 A 的同一 Caddyfile 添加：

```caddyfile
risk.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:4100
}
```

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
curl -fsS https://risk.example.com/health
```

## 4. API 权限模型

Client ID/Secret 不是后台账号。站点请求必须按协议签名，时间偏差和 nonce 重放都会被拒绝。源码使用的能力范围包括：

| Scope | 用途 |
|---|---|
| `risk.events.write` | 上报风险事件/信号 |
| `risk.decisions.read` | 获取当前决定 |
| `risk.policy.read` | 获取策略版本和规则 |
| `maintenance.inventory.write` | 上报版本/组件清单 |
| `maintenance.advisory.read` | 读取维护建议 |
| `maintenance.test-result.write` | 写入维护测试结果 |

只给导航站实际需要的范围。分析接口的 Bearer 临时令牌和维护读取令牌具有短期用途，不应作为长期客户端 Secret。

## 5. 第三方账号与最小权限

### 5.1 Telegram 与 Bark

风险中心有两组 Telegram 配置：

1. 告警 Bot：Bot Token、Chat ID；只需向指定会话发送消息。
2. Backup Bot：独立 Bot Token、Chat ID；只用于规则备份分片。

Bark 配置为服务 URL、Device Key 和分组。通知顺序固定为：Telegram 重试 → Telegram 最终失败 → Bark；Telegram 成功时不重复推 Bark。

不要给机器人无关的管理员权限。频道场景只授予发布消息；群组场景确认 Bot 可以发言。Backup Bot 与告警 Bot 不要复用。

### 5.2 Google Drive OAuth

维护备份需要 Google Cloud 项目、OAuth Consent Screen、启用的 Google Drive API，以及“Web application”类型 OAuth Client ID/Secret。

生产 Redirect URI 必须精确填写后台显示的 HTTPS 回调地址，例如：

```text
https://risk.example.com/api/admin/maintenance/google-drive/oauth/callback
```

实际路径以后台显示值为准，不能多斜杠、通配符或 HTTP。最小 scopes：

- `openid`
- `email` / `https://www.googleapis.com/auth/userinfo.email`
- `https://www.googleapis.com/auth/drive.file`

`drive.file` 只允许访问此应用创建或用户明确选取的文件，不要改为完整 `drive`。测试模式要把使用账号加入 Test users；发布前按 Google 要求配置应用信息和隐私说明。

### 5.3 GitHub API Token

`BOT_RISK_GITHUB_TOKEN` 仅用于上游版本和发布信息读取，公开仓库可不填。若共享出口触发匿名限速，可创建 Fine-grained PAT：

- Repository access：只选择需要检查的仓库；若全部是公开仓库，可优先不填 Token。
- Repository permissions：`Contents: Read`、`Metadata: Read`（Metadata 通常自动授予）。
- 不需要 Issues、Pull requests、Actions、Secrets、Administration 或写权限。
- 设置过期时间并仅保存在风险中心加密库/环境文件。

### 5.4 CrowdSec（可选）

需要 CrowdSec LAPI URL 和为风险中心创建的 LAPI machine/API key。LAPI 只监听回环或私网；不要公开 8080。只给读取决定/告警所需能力。采集日志时将日志目录只读挂载给 CrowdSec，不要挂载整个应用目录。

### 5.5 npm Registry

维护检查读取公开 npm 元数据不需要 Token。风险中心不应持有 npm 发布 Token；发布权限属于控制中心。

## 6. 首次后台操作

1. 用 `admin/admin123` 登录后立即修改密码，确认旧会话被撤销。
2. 创建/核对站点，生成 Client ID/Secret；明文 Secret 仅保存一次。
3. 导航站先设置观察模式，测试事件上报、策略读取和决定读取。
4. 创建一条测试疑似访客，验证证据、人工处置、审计和命中次数。
5. 分别测试 Telegram、模拟 Telegram 失败后的 Bark、Backup Bot 和立即备份。
6. 如需 Google Drive，完成 OAuth 授权并执行测试备份。
7. 确认所有行为正常后，再把导航站切换为执行模式。

## 7. 数据库、备份与保留

- PostgreSQL 是规则、站点、凭据元数据、事件、审计、维护和告警记录的事实来源。
- Redis 是短期状态；不能用 Redis 备份替代 PostgreSQL 备份。
- 数据库备份使用 `pg_dump -Fc`；恢复前核对迁移版本和应用 commit。
- 规则 Telegram 备份不包含所有访客临时数据，也不等价于完整数据库备份。
- `EVENT_RETENTION_DAYS` 默认 7，可设 1–90；延长保留期会增加隐私和容量压力。

```bash
sudo -u postgres pg_dump -Fc botrisk > /secure-backups/botrisk-$(date +%F-%H%M).dump
```

备份目录应为 root 管理、非 Web 可读，并建立离线副本与恢复演练。

## 8. 更新和回滚

```bash
sudo systemctl stop bot-risk-center
sudo -u postgres pg_dump -Fc botrisk > /secure-backups/botrisk-pre-update.dump
cd /opt/bot-risk-center
sudo -u apps git fetch --all --prune
sudo -u apps git pull --ff-only
sudo -u apps npm ci --omit=dev
sudo -u apps npm test
sudo systemctl start bot-risk-center
curl -fsS http://127.0.0.1:4100/ready
```

迁移在启动时执行。发生失败时先保存日志和数据库快照，再恢复兼容的 commit/数据库；不要在不理解迁移影响时手工删除表或规则。

## 9. 上线验收

- `/health` 和 `/ready` 均正常，PostgreSQL/Redis 检查通过。
- 公网后台 HTTPS 可登录，4100 不能从公网 IP 直接访问。
- 管理员密码已更换，Cookie、CSRF、退出和会话撤销正常。
- 导航站签名请求通过；错误密钥、过期时间和重复 nonce 被拒绝。
- 观察模式只记录不拦截，执行模式正确应用人工决定。
- Telegram 成功时 Bark 不发送；Telegram 最终失败时 Bark 发送一次。
- 规则备份可恢复，解密密钥与备份分离。
- 审计日志不包含 Bot Token、Client Secret、OAuth refresh token 或数据库密码。

## 10. 故障排查

- **地址或凭据验证失败**：核对导航站使用的 Client ID、风险中心 `BOT_RISK_CLIENTS_JSON` 的键和值、时钟同步和 URL；Secret 轮换后旧值立即失效。
- **测试按钮 500**：查看 `journalctl -u bot-risk-center` 的同一请求时间；常见原因是加密主密钥变化、上游超时或数据库迁移失败。
- **Telegram 成功但仍收到 Bark**：检查是否运行旧代码或存在两个告警进程；当前逻辑只允许失败兜底。
- **规则不执行**：确认导航站不是观察模式、站点标识一致、策略版本已同步，且规则未停用/过期。
- **Google `redirect_uri_mismatch`**：后台回调 URL 与 Google Console 中的 Authorized redirect URI 必须逐字一致。

## 11. 安全注意事项

- `BOT_RISK_CREDENTIAL_KEY`、数据库密码、客户端 Secret、Bot Token 和 OAuth Client Secret 不得提交。
- 风险中心监听回环/私网；公网只经 Caddy HTTPS。
- 管理员、API Client、维护令牌和分析令牌用途完全不同，禁止互换。
- 人工规则可影响真实访问，先预览、再观察、最后执行；每次变更保留审计与备份。
- 初始 `admin/admin123` 只是部署约定，必须在首次登录立即替换。

## 12. 许可

使用 GitHub、Google Drive、Telegram、Bark、CrowdSec、npm 和上游安全情报时，分别遵守其条款。不要通过风险中心重新分发无再分发授权的原始数据。

官方权限参考：[Google OAuth Web Server](https://developers.google.com/identity/protocols/oauth2/web-server)、[Google API Scopes](https://developers.google.com/identity/protocols/oauth2/scopes)、[GitHub Fine-grained PAT 权限](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)。
