#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${LOG_DIR:-$BASE_DIR/logs}"

mkdir -p "$LOG_DIR"

# 1) Delete prompt/response logs older than 7 days (if present)
find "$LOG_DIR" -type f \( -name '*prompt*.log*' -o -name '*response*.log*' \) -mtime +7 -delete || true

# 2) Purge expired session snapshots older than 1 day
find "$BASE_DIR" -type f -name 'session-*.json' -mtime +1 -delete || true

# 3) Anonymize analytics older than 90 days (simple replacement in archived jsonl)
find "$LOG_DIR/archive" -type f -name '*.jsonl' -mtime +90 -print0 2>/dev/null | while IFS= read -r -d '' f; do
  sed -E 's/"ip":"[^"]+"/"ip":"[ANON]"/g; s/"user_id":"[^"]+"/"user_id":"[ANON]"/g; s/"api_key":"[^"]+"/"api_key":"[ANON]"/g' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
done
