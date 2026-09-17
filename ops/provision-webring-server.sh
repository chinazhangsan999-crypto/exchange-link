#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run this script with sudo." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
APP_OWNER="${SUDO_USER:-root}"
APP_HOME="$(getent passwd "${APP_OWNER}" | cut -d: -f6)"

apt-get update
apt-get install -y \
  ca-certificates \
  curl \
  debian-keyring \
  debian-archive-keyring \
  apt-transport-https \
  gnupg \
  git \
  build-essential \
  sqlite3 \
  unzip \
  logrotate

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
  | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
  > /etc/apt/sources.list.d/nodesource.list

curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
  | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
  > /etc/apt/sources.list.d/caddy-stable.list
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
chmod o+r /etc/apt/sources.list.d/caddy-stable.list

apt-get update
apt-get install -y nodejs caddy
npm install --global pm2

# Caddy is installed but intentionally kept off until a reviewed production
# configuration and Cloudflare origin/firewall policy are ready.
systemctl disable --now caddy || true

install -d -m 0755 -o "${APP_OWNER}" -g "${APP_OWNER}" "${APP_HOME}/app"
install -d -m 0700 -o "${APP_OWNER}" -g "${APP_OWNER}" "${APP_HOME}/app-secrets"

runuser -u "${APP_OWNER}" -- env HOME="${APP_HOME}" pm2 install pm2-logrotate
runuser -u "${APP_OWNER}" -- env HOME="${APP_HOME}" pm2 set pm2-logrotate:max_size 20M
runuser -u "${APP_OWNER}" -- env HOME="${APP_HOME}" pm2 set pm2-logrotate:retain 14
runuser -u "${APP_OWNER}" -- env HOME="${APP_HOME}" pm2 save --force
pm2 startup systemd -u "${APP_OWNER}" --hp "${APP_HOME}"

# Hand ownership of the daemon to systemd. Starting the service while a
# manually spawned daemon is alive makes systemd reject the pre-existing PID.
runuser -u "${APP_OWNER}" -- env HOME="${APP_HOME}" pm2 kill
systemctl reset-failed "pm2-${APP_OWNER}" || true
systemctl start "pm2-${APP_OWNER}"

echo "Provisioning completed for ${APP_OWNER}."
