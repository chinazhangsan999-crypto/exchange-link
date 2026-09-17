#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 sudo 执行安装脚本。" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_USER="${APP_USER:-niaiwo}"
APP_HOME="$(getent passwd "${APP_USER}" | cut -d: -f6)"
if [[ -z "${APP_HOME}" ]]; then
  echo "找不到应用用户：${APP_USER}" >&2
  exit 1
fi
if ! grep -Eq '^[[:space:]]*import[[:space:]]+cloudflare-ips\.caddy[[:space:]]*$' /etc/caddy/Caddyfile; then
  echo "/etc/caddy/Caddyfile 尚未导入 cloudflare-ips.caddy，请先部署仓库中的 ops/Caddyfile。" >&2
  exit 1
fi

install -d -m 0755 /usr/local/lib/webring-cloudflare-ip-sync
install -m 0644 "${SCRIPT_DIR}/cloudflare-ip-sync-helper.js" /usr/local/lib/webring-cloudflare-ip-sync/cloudflare-ip-sync-helper.js
install -m 0755 "${SCRIPT_DIR}/webring-cloudflare-ip-sync" /usr/local/sbin/webring-cloudflare-ip-sync
install -m 0644 "${SCRIPT_DIR}/webring-cloudflare-ip-sync.service" /etc/systemd/system/webring-cloudflare-ip-sync.service
install -m 0644 "${SCRIPT_DIR}/webring-cloudflare-ip-sync.timer" /etc/systemd/system/webring-cloudflare-ip-sync.timer
if [[ ! -f /etc/caddy/cloudflare-ips.caddy ]]; then
  install -m 0644 "${SCRIPT_DIR}/cloudflare-ips.caddy" /etc/caddy/cloudflare-ips.caddy
fi

install -d -m 0755 "${APP_HOME}/app/data"
cat > /etc/default/webring-cloudflare-ip-sync <<EOF
STATE_FILE=${APP_HOME}/app/data/cloudflare-ip-whitelist-state.json
EOF
chmod 0644 /etc/default/webring-cloudflare-ip-sync

SYSTEMCTL_BIN="$(command -v systemctl)"
SUDOERS_FILE=/etc/sudoers.d/webring-cloudflare-ip-sync
printf '%s ALL=(root) NOPASSWD: %s start webring-cloudflare-ip-sync.service\n' "${APP_USER}" "${SYSTEMCTL_BIN}" > "${SUDOERS_FILE}"
chmod 0440 "${SUDOERS_FILE}"
visudo -cf "${SUDOERS_FILE}"

caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl reload caddy
systemctl daemon-reload
systemctl enable --now webring-cloudflare-ip-sync.timer
systemctl start webring-cloudflare-ip-sync.service
echo "Cloudflare IP 自动同步已安装；后台可通过固定 systemd 单元手动触发。"
