#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${BASE_DIR:-$HOME/.assistant-ops-dashboard/certbot}"
CONFIG_DIR="$BASE_DIR/config"
WORK_DIR="$BASE_DIR/work"
LOGS_DIR="$BASE_DIR/logs"

mkdir -p "$CONFIG_DIR" "$WORK_DIR" "$LOGS_DIR"

# Renews any existing certs in CONFIG_DIR. Requires initial cert issuance first.
certbot renew \
  --config-dir "$CONFIG_DIR" \
  --work-dir "$WORK_DIR" \
  --logs-dir "$LOGS_DIR" \
  --quiet
