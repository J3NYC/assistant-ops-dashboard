#!/usr/bin/env bash
set -euo pipefail

FILE="${1:-}"
if [ -z "$FILE" ]; then
  echo "Usage: $0 <backup-file.gpg>" >&2
  exit 1
fi

if [ -z "${BACKUP_PASSPHRASE:-}" ]; then
  echo "BACKUP_PASSPHRASE env var required" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

gpg --batch --yes --passphrase "$BACKUP_PASSPHRASE" -o "$TMP_DIR/backup.tar.gz" -d "$FILE"
tar -tzf "$TMP_DIR/backup.tar.gz" >/dev/null

echo "Backup decryption verified: $FILE"
