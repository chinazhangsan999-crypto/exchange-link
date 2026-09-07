#!/usr/bin/env bash
set -euo pipefail

LOG=/home/niaiwo/.pm2/logs/webring-error.log
if [[ -f "$LOG" ]]; then
  grep -F '[Webhook Alert Error]' "$LOG" | tail -n 20 || true
fi
