# Webring Navigation

[中文文档](README.md)

Webring Navigation is a multi-site friend-link, traffic exchange, advertising, bot-control, risk-decision, and disaster-recovery application. The repository also contains a development copy of the risk-center source, but production runs the risk center as an independent service.

> This document reflects the current source. Domains, identities, tokens, passwords, and HMAC keys are placeholders. Real secrets belong only in server-side environment files or encrypted credential stores and must never be committed.

## 1. Capabilities

- Sites, categories, tags, ordering, cards, detail pages, applications, moderation, reciprocal-link checks, health checks, pings, ingress/egress analytics, and traffic matrices.
- Local and control-center advertising, image/code creatives, placement policy, and an isolated ad Edge for third-party code.
- Separate public frontend, API Edge, admin Edge, and ad Edge Workers.
- Admin sessions and CSRF, separate admin/guest JWT keys, PoW/read tokens, BotD, WebDriver signals, and verified-search-crawler handling.
- Bot gate modes `off`, `observe`, and `enforce`; asynchronous risk-center events and decision caching.
- SQLite persistence, encrypted Telegram backups, audit trails, and retryable notifications.
- Encrypted recovery manifests, cached standalone recovery UI, DNS TXT A/B/R1 shares, publish/readback/rollback, three resolver tiers, and a 128-route ceiling.
- Integrations with the control center, risk center, IP Intelligence service, Telegram, Bark fallback, webhooks, Cloudflare, and multiple authoritative DNS providers.

## 2. Recommended production topology

| Server | Service | Bind address | Public endpoint |
|---|---|---|---|
| A | Navigation | `127.0.0.1:3001` | `nav.example.com`, `admin.example.com`, API/Worker hostnames |
| A | Risk Center | `127.0.0.1:4100` | `risk.example.com` |
| B | Control Center | `127.0.0.1:3100` | `control.example.com` |
| B | IP Intelligence | `127.0.0.1:3101` | `ip.example.com` |

Expose only SSH, HTTP, and HTTPS. Never expose PostgreSQL, Redis, or the Node listener ports. Configure cross-system credentials later in the admin consoles; this guide deliberately does not auto-provision shared secrets.

## 3. Requirements

- Ubuntu 22.04/24.04 LTS; 2 vCPU, 4 GiB RAM, and 30 GiB SSD or better.
- Node.js 22 LTS, Caddy 2, Git, SQLite3, and build tools.
- PostgreSQL 16/17 and Redis 7 for the co-hosted risk center.
- Dedicated HTTPS hostnames. With Cloudflare proxying, use **Full (strict)**.
- A non-root service account; examples use `apps`.

## 4. Build server A from a clean host

### 4.1 Packages and account

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

Install Caddy from its official Debian/Ubuntu repository. Do not publish an unconfigured origin.

### 4.2 Clone and install

Use a read-only GitHub Deploy Key with only `Contents: Read`; do not paste a personal token into shell history.

```bash
sudo -u apps git clone https://github.com/zhangsan4188/webring-navigation.git /opt/webring-navigation
cd /opt/webring-navigation
sudo -u apps npm ci --omit=dev
sudo -u apps npm run build:public-frontend
```

The mirror is `https://github.com/chinazhangsan999-crypto/exchange-link.git`.

### 4.3 Environment

Generate independent values, one command per secret:

```bash
openssl rand -hex 32
openssl rand -base64 48
```

Create `/etc/webring-navigation/navigation.env`:

```dotenv
NODE_ENV=production
PORT=3001
SESSION_SECRET=<unique-random-value>
ADMIN_JWT_SECRET=<different-random-value>
GUEST_JWT_SECRET=<different-random-value>
FRONTEND_PROXY_SECRET=<shared-only-with-api-and-admin-workers>
EDGE_ACCESS_SECRET=<origin-only-secret>
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

Production requires `SESSION_SECRET`, `ADMIN_JWT_SECRET`, `GUEST_JWT_SECRET`, and `FRONTEND_PROXY_SECRET`. They must be distinct. Rotation invalidates existing sessions or signatures.

The requested first-run credentials are `admin/admin123`. They are bootstrap-only and are not a safe long-term production credential. Change the password immediately and disable local password access after enrollment where appropriate.

### 4.4 systemd

Create `/etc/systemd/system/webring-navigation.service`:

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

SQLite initializes on first start. Make backup directories writable by `apps` and mode `700`; never track the live database or backups in Git.

### 4.5 Caddy

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

Worker-fronted admin/API origins also need Cloudflare-source restrictions and Worker-to-origin request signing. Never trust a visitor-supplied `X-Forwarded-For`. With Cloudflare proxying enabled, point DNS to server A and ensure ACME/origin certificate validation works; Full (strict) rejects an invalid origin certificate.

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
curl -fsS https://nav.example.com/api/health
```

## 5. First-time configuration order

1. Sign in with `admin/admin123` and immediately replace the bootstrap password.
2. Deploy public frontend, API Edge, and admin Edge Workers; confirm their secrets match the origin.
3. Add exact allowed frontend origins—no wildcards.
4. Start the bot gate in `observe`; use `enforce` only after reviewing production data.
5. Create a site in the control center and verify/save its one-time site credential.
6. Create a risk-center Client ID/Secret, select observe or enforcement mode, and verify/save it.
7. Create a dedicated IP Intelligence client and verify/save its credentials.
8. Configure DNS channels, A/B/R1 records, and three-tier resolver routes; always perform DoH readback after publishing.
9. Configure and separately test the Telegram alert bot, Bark fallback, and Telegram backup bot.

## 6. Third-party accounts and least privilege

### 6.1 Cloudflare

Required values depend on the feature: Account ID, Zone, API token, Worker/route names, and hostnames.

- Worker deployment: Account `Workers Scripts: Edit`; selected Zone `Workers Routes: Edit` and `Zone: Read`.
- Automated DNS changes: selected Zone `DNS: Edit`; use `DNS: Read` for read-only diagnostics.
- Control-center Pages publishing uses a separate token: Account `Cloudflare Pages: Edit`; selected Zone `Zone: Read` and `DNS: Edit`.
- Restrict every token to the exact account and zones. Do not select all accounts or all zones.

`FRONTEND_PROXY_SECRET` is an application secret shared only by the Worker and navigation origin; it is not a Cloudflare token. Keep `EDGE_ACCESS_SECRET` origin-side only.

### 6.2 Recovery DNS providers

| Provider | Fields | Minimum actions | Notes |
|---|---|---|---|
| Cloudflare DNS | Account ID, API Token | selected Zone `Zone: Read`, `DNS: Edit` | Do not add Worker permissions to a TXT-only token |
| deSEC | Token | read/write RRsets in selected zone | Use a dedicated, zone-limited token |
| ClouDNS | Auth ID or Sub-auth ID, Auth Password | list zones/records, create/delete records | HTTP API availability may depend on the paid plan |
| AWS Route 53 | Access Key ID, Secret; Session Token for temporary credentials | `ListHostedZonesByName`, `ListResourceRecordSets`, `ChangeResourceRecordSets` | Restrict IAM to hosted zone, TXT type, and `_recovery*`; prefer STS |
| Tencent DNSPod | SecretId, SecretKey | `DescribeDomainList`, `DescribeRecordList`, `CreateRecord`, `DeleteRecord` | Use a CAM sub-user and selected domain resources |
| Alibaba Cloud AliDNS | AccessKey ID, AccessKey Secret | `DescribeDomains`, `DescribeDomainRecords`, `AddDomainRecord`, `DeleteDomainRecord` | Use RAM and a selected domain ARN |
| Baidu Cloud DNS | Access Key ID, Secret Access Key | list zones/records, create/delete records | Use a sub-user scoped to the zone |
| Volcengine DNS | Access Key, Secret Key, Region; optional Session Token | `ListZones`, `ListRecords`, `CreateRecord`, `DeleteRecord` | Use an IAM sub-user scoped to DNS resources |
| Hurricane Electric | none for automation | manual publishing | Current source does not automate writes |

Read, create, and delete are all needed because the application publishes a new generation, verifies it, and cleans old fragments. Domain registration, transfer, billing, and account-administration permissions are unnecessary.

### 6.3 Telegram, Bark, and webhooks

- Alert bot: Bot Token and Chat ID; grant only the ability to send messages to the target chat/channel.
- Backup bot: separate Bot Token and Chat ID, restricted to a dedicated backup conversation.
- Bark: server URL and Device Key; it runs only after Telegram has definitively failed.
- Webhook: dedicated HTTPS URL and random signing secret when enabled.

Encrypted backup data and its decryption key must be stored separately.

### 6.4 Internal system credentials

Generate and never reuse these credentials:

- Control-center site credential, displayed once on create/rotate.
- Risk-center Client ID/Secret; secret is at least 32 characters and site key must match.
- IP Intelligence Client ID/Secret, one pair per navigation site.

Use `http://127.0.0.1:4100` for the co-hosted risk center. Cross-server connections require HTTPS. Disabling an integration stops future synchronization but does not erase data already held by the other service.

## 7. Important environment variables

| Variable | Requirement | Purpose |
|---|---|---|
| `SESSION_SECRET` | production required | session signing |
| `ADMIN_JWT_SECRET` | production required | admin-token signing |
| `GUEST_JWT_SECRET` | production required | guest/verification-token signing |
| `FRONTEND_PROXY_SECRET` | production required | Edge-to-origin signing, at least 32 characters |
| `ADMIN_FRONTEND_ORIGIN` | recommended | single trusted admin Origin |
| `FRONTEND_PROXY_API_HOSTS` | recommended | allowed proxy hostnames |
| `INITIAL_ADMIN_PASSWORD` | bootstrap | at least 8; use 12+ in production |
| `TRUSTED_PROXIES` | topology-specific | actual proxies only |
| `BOT_GATE_MODE` | optional | `off`, `observe`, or `enforce` |
| `BOT_RISK_*` | when enabled | URL, client ID, secret, site key, timeouts |
| `CONTROL_CENTER_*` | when enabled | URL and credential or mode-0600 credential file |
| `IP_INTELLIGENCE_*` | when enabled | URL and client credentials/file |
| `PUBLIC_CODE_ADS_ENABLED` | optional | global code-ad switch |
| `DIRECT_CODE_ADS_ENABLED` | optional | direct code-ad switch |
| `SANDBOX_CODE_ADS_ENABLED` | optional | sandbox code-ad switch |

## 8. Upgrade, verification, and rollback

Back up SQLite, environment files, and credential directories first; secret backups must stay outside release archives.

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

If no aggregate `npm test` script exists, that is not a passing test. Run the repository's `node --test` files plus:

```bash
node --check server.js
git diff --check
```

Rollback must pair a known-good commit with a compatible database backup.

## 9. Acceptance checklist

- systemd is active and local plus public health checks return 200.
- Admin login, CSRF, logout, and password change work; the origin IP cannot bypass the admin Edge.
- A test friend-link completes application, approval, detail, redirect, and analytics flows.
- Control, risk, and IP connection tests pass with matching client/site identifiers.
- TXT publish, three-tier DoH readback, offline recovery UI, and A/B/R1 generation confirmation pass.
- Telegram succeeds; Bark triggers only in a simulated final Telegram failure.
- Database, credentials, and backups have expected ownership/modes; no secret appears in logs, HTML, Git, or process arguments.

## 10. Troubleshooting

- **Admin 404:** inspect the Admin Worker route, `ADMIN_FRONTEND_ORIGIN`, allowed origins, and API Edge hosts; do not first loosen the origin.
- **Risk credential rejected:** Client ID must match exactly. A rotated one-time secret immediately invalidates the old value.
- **DNS API succeeded but readback failed:** verify authoritative NS, selected provider zone, complete TXT fragments, TTL, and resolver propagation. API acceptance is not global propagation.
- **ClouDNS says the HTTP API is unavailable:** confirm the account plan includes HTTP API access.
- **Recovery UI remains on “reading manifest”:** verify the Service Worker belongs to the current origin, all fragments for the generation are present, and at least one resolver tier succeeds. Unregister stale Service Workers before retesting.
- **All clients have one IP or spoofed IPs:** trust only real proxies and make the proxy overwrite, not append, client-controlled forwarding headers.

## 11. Security invariants

- Never commit `.env`, databases, backups, Worker secrets, tokens, client secrets, or OAuth refresh tokens.
- Use distinct credentials per system, site, and purpose; revoke abandoned hosts and users.
- Admin/API traffic is HTTPS-only; databases and Redis stay on loopback/private networks.
- Scope tokens to minimum actions/resources and record expiry plus rotation ownership.
- Logs expose only a fingerprint or “configured” state, never plaintext credentials.
- Observe before enforcing. Rules, DNS publishing, and key rotation require an audit entry and rollback point.

## 12. Licensing

Repository licensing is separate from third-party service and data terms. Review the applicable DNS, Cloudflare, Telegram, Bark, database, and recovery-data terms before production or redistribution.

Official permission references: [Cloudflare API-token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/), [Route 53 service actions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_route53.html), and [fine-grained Route 53 record permissions](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-permissions.html).
