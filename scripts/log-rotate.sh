#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="${LOG_DIR:-$(cd "$(dirname "$0")/.." && pwd)/logs}"
mkdir -p "$LOG_DIR/archive/security" "$LOG_DIR/archive/general"

TODAY="$(date +%F)"

for f in "$LOG_DIR"/*.log.jsonl; do
  [ -f "$f" ] || continue
  base="$(basename "$f")"
  cp "$f" "$LOG_DIR/archive/${base%.log.jsonl}-$TODAY.log.jsonl"
  : > "$f"
done

# compress archives older than 1 day
find "$LOG_DIR/archive" -type f -name '*.log.jsonl' -mtime +1 -exec gzip -f {} \;

# retain security logs 365 days
find "$LOG_DIR/archive" -type f \( -name '*security*.gz' -o -name '*security*.log.jsonl' \) -mtime +365 -delete

# retain general logs 30 days
find "$LOG_DIR/archive" -type f \( -name '*app*.gz' -o -name '*app*.log.jsonl' \) -mtime +30 -delete
