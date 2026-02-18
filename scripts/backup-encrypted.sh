#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${BACKUP_DIR:-$BASE_DIR/backups}"
mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"

TMP_TAR="$OUT_DIR/assistant-ops-$STAMP.tar.gz"
ENC_OUT="$OUT_DIR/assistant-ops-$STAMP.tar.gz.gpg"

# Include config + logs (excluding node_modules/certs)
tar -czf "$TMP_TAR" \
  --exclude='node_modules' \
  --exclude='certs' \
  -C "$BASE_DIR" .

if [ -z "${BACKUP_PASSPHRASE:-}" ]; then
  echo "BACKUP_PASSPHRASE env var required" >&2
  exit 1
fi

gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase "$BACKUP_PASSPHRASE" -o "$ENC_OUT" "$TMP_TAR"
rm -f "$TMP_TAR"

echo "Encrypted backup written: $ENC_OUT"
