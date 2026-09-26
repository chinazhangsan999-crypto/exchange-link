# Bot Risk Center

[中文文档](README.md)

Bot Risk Center is an independent behavior-analysis, policy, manual-action, alerting, and maintenance-intelligence service. It ingests signed navigation events and returns observe/enforce decisions; it does not replace the navigation application's own browser gate.

> Real credentials belong only in server-side environment files or the encrypted credential store. Every value in this guide is a placeholder.

## 1. Features

- HMAC client authentication, event ingestion, policy reads, and decision reads.
- Site and client lifecycle, one-time secret display, rotation, and connection status.
- Suspect visitors, evidence timelines, signal aggregation, and manual allow/block/observe actions.
- Unified manual rules, revisions, preview, status, audit, and encrypted Telegram backups.
- Signals for known AI crawlers, replay, scanning, concurrency, BotD, WebDriver, and verification failures.
- PostgreSQL persistence, Redis short-lived state/cache, and retention cleanup.
- Telegram-first alerts with Bark only after final Telegram failure.
- A separate Backup Bot sending AES-256-GCM encrypted rule fragments.
- Google Drive maintenance backups and GitHub/npm upstream-version checks.
- Optional CrowdSec LAPI integration while the service remains privately bound.

## 2. Placement

Run it with Navigation on server A:

- Navigation `127.0.0.1:3001`
- Risk Center `127.0.0.1:4100`
- PostgreSQL `127.0.0.1:5432`
- Redis `127.0.0.1:6379`
- Caddy exposes `risk.example.com` on 443

Navigation may use `http://127.0.0.1:4100` locally. The public admin endpoint still uses HTTPS. Never expose 4100, 5432, or 6379.

## 3. Clean-host installation

### 3.1 PostgreSQL and Redis

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

Start with an empty database; migrations run on application initialization. Generate the database password instead of copying the placeholder.

### 3.2 Clone and install

```bash
sudo -u apps git clone https://github.com/zhangsan4188/bot-risk-center.git /opt/bot-risk-center
cd /opt/bot-risk-center
sudo -u apps npm ci --omit=dev
```

Mirror: `https://github.com/chinazhangsan999-crypto/bot-risk-center.git`. A Deploy Key needs only `Contents: Read`.

### 3.3 Generate bootstrap and application secrets

The requested bootstrap convention is `admin` / `admin123`; replace it immediately with a unique 12+ character password. Generate the compatible hash:

```bash
node -e "const c=require('node:crypto');const p=process.argv[1];const s=c.randomBytes(16).toString('hex');c.scrypt(p,s,64,(e,d)=>{if(e)throw e;console.log('scrypt$'+s+'$'+d.toString('hex'))})" 'admin123'
openssl rand -base64 48  # BOT_RISK_CREDENTIAL_KEY
openssl rand -base64 48  # per-navigation client secret
```

### 3.4 Environment

Create `/etc/bot-risk-center/risk.env`:

```dotenv
NODE_ENV=production
PORT=4100
RISK_LISTEN_HOST=127.0.0.1
DATABASE_URL=postgres://botrisk:<database-password>@127.0.0.1:5432/botrisk
REDIS_URL=redis://127.0.0.1:6379
BOT_RISK_ADMIN_USERNAME=admin
BOT_RISK_ADMIN_PASSWORD_HASH=<complete-scrypt-value>
BOT_RISK_CREDENTIAL_KEY=<stable-value-at-least-32-characters>
BOT_RISK_INTERNAL_URL=http://127.0.0.1:4100
BOT_RISK_PUBLIC_URL=https://risk.example.com
BOT_RISK_CLIENTS_JSON={"nav-main":"<dedicated-secret-at-least-32-characters>"}
EVENT_RETENTION_DAYS=7
CROWDSEC_LAPI_URL=
CROWDSEC_LAPI_KEY=
BOT_RISK_GITHUB_TOKEN=
```

```bash
sudo chown root:apps /etc/bot-risk-center/risk.env
sudo chmod 640 /etc/bot-risk-center/risk.env
```

The credential key encrypts third-party credentials. Losing it makes stored ciphertext unrecoverable. Assign a unique client secret to each site.

### 3.5 systemd and Caddy

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

```caddyfile
risk.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:4100
}
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bot-risk-center
curl -fsS http://127.0.0.1:4100/ready
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
curl -fsS https://risk.example.com/health
```

## 4. API scopes

| Scope | Purpose |
|---|---|
| `risk.events.write` | submit risk events/signals |
| `risk.decisions.read` | read current decisions |
| `risk.policy.read` | read policy/rule versions |
| `maintenance.inventory.write` | submit version/component inventory |
| `maintenance.advisory.read` | read maintenance advice |
| `maintenance.test-result.write` | submit maintenance test results |

Grant only the scopes a site needs. Short-lived analysis bearer tokens and maintenance read tokens are not long-lived client secrets. Clock skew and nonce replay are rejected.

## 5. Third-party accounts and minimum permissions

### 5.1 Telegram and Bark

- Alert Bot Token and Chat ID: send-message permission to one target only.
- Separate Backup Bot Token and Chat ID: encrypted rule backup only.
- Bark server URL, Device Key, and group: fallback after Telegram retries finally fail.

Do not grant unrelated Telegram administrator rights. Never reuse the alert bot for backups. Store backup ciphertext and the decryption key separately.

### 5.2 Google Drive OAuth

Create a Google Cloud project, configure an OAuth consent screen, enable Drive API, and create a **Web application** OAuth client. Add the exact HTTPS callback shown by the admin UI, for example:

```text
https://risk.example.com/api/admin/maintenance/google-drive/oauth/callback
```

Use only:

- `openid`
- `email` / `https://www.googleapis.com/auth/userinfo.email`
- `https://www.googleapis.com/auth/drive.file`

`drive.file` limits access to files created or explicitly selected through this app. Do not replace it with broad `drive`. Add test users while the consent screen is in testing.

### 5.3 GitHub token

`BOT_RISK_GITHUB_TOKEN` is optional for public upstream data. To avoid anonymous rate limits, use a fine-grained PAT with only selected repositories, `Contents: Read`, and `Metadata: Read`; no Issues, PR, Actions, Secrets, Administration, or write permission. Set an expiry.

### 5.4 CrowdSec

Optionally supply a private LAPI URL and dedicated machine/API key. Keep LAPI on loopback/private networking. Mount only required logs read-only into CrowdSec.

### 5.5 npm

Public registry checks require no token. Never store an npm publishing token in the risk center; publishing belongs to the control center.

## 6. First admin workflow

1. Sign in with `admin/admin123`, immediately change the password, and revoke old sessions.
2. Create/verify sites and clients; save a displayed secret once.
3. Start Navigation in observe mode and test events, policy reads, and decisions.
4. Generate a test suspect and verify evidence, manual action, audit, and hit counts.
5. Separately test Telegram, Bark under forced Telegram failure, Backup Bot, and immediate backup.
6. Complete Google OAuth and a test backup if Drive is used.
7. Move Navigation to enforce mode only after observation is correct.

## 7. Data, backup, and retention

- PostgreSQL is authoritative for sites, rules, credential metadata, events, audit, maintenance, and alerts.
- Redis is ephemeral and is not a database backup.
- Use `pg_dump -Fc`; restore only with a compatible application/migration version.
- Telegram rule backup is not a full database backup and omits transient visitor data.
- `EVENT_RETENTION_DAYS` accepts 1–90; longer retention increases privacy and capacity costs.

```bash
sudo -u postgres pg_dump -Fc botrisk > /secure-backups/botrisk-$(date +%F-%H%M).dump
```

Keep backups root-managed, non-Web-accessible, offline-copied, and periodically restore-tested.

## 8. Upgrade and rollback

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

Migrations run at startup. Preserve logs and a database snapshot before rollback; never delete tables or rules to “fix” an unknown migration error.

## 9. Acceptance checklist

- `/health` and `/ready` pass, including PostgreSQL and Redis.
- HTTPS admin works and 4100 is not directly public.
- Bootstrap password is replaced; cookies, CSRF, logout, and session revocation work.
- Valid signed navigation requests pass; wrong secret, stale timestamp, and nonce replay fail.
- Observe records without blocking; enforce applies the intended manual decision.
- Bark stays silent on Telegram success and fires once on final Telegram failure.
- Rule backup restores successfully, with key and ciphertext separated.
- No bot token, client secret, OAuth refresh token, or DB password appears in audit/log output.

## 10. Troubleshooting

- **Address or credential validation failed:** compare the exact Client ID, `BOT_RISK_CLIENTS_JSON`, server clocks, and URL. Rotation invalidates the old secret immediately.
- **Test returns 500:** correlate `journalctl -u bot-risk-center` by timestamp; common causes are a changed encryption key, upstream timeout, or failed migration.
- **Bark despite Telegram success:** check for old code or duplicate alert processes; current behavior is fallback-only.
- **Rule does not execute:** confirm Navigation is not observing, site identifiers and policy revisions match, and the rule is enabled/not expired.
- **Google `redirect_uri_mismatch`:** the callback and Authorized redirect URI must match character-for-character.

## 11. Security invariants

- Never commit the credential key, DB password, client secrets, bot tokens, or OAuth secrets.
- Bind privately; expose only Caddy HTTPS.
- Admin accounts, API clients, maintenance tokens, and analysis tokens are distinct identities.
- Preview and observe before enforcing manual rules; preserve audit plus backup for every change.
- `admin/admin123` is bootstrap-only and must be replaced at first login.

## 12. Licensing

Comply separately with GitHub, Google Drive, Telegram, Bark, CrowdSec, npm, and upstream intelligence terms. Do not redistribute source data without redistribution rights.

Official permission references: [Google OAuth for web servers](https://developers.google.com/identity/protocols/oauth2/web-server), [Google API scopes](https://developers.google.com/identity/protocols/oauth2/scopes), and [GitHub fine-grained PAT permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens).
