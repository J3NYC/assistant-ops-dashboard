# Assistant Ops Dashboard

![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933?logo=node.js&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![OpenClaw](https://img.shields.io/badge/built%20for-OpenClaw-7c3aed)

A lightweight self-hosted dashboard for monitoring and controlling an OpenClaw assistant environment.

## Features

### Core Ops
- OpenClaw health/status check
- Raw status output for quick debugging
- Gateway restart action from the UI

### CI Failure Summarizer (GitHub Actions)
- Fetches recent failed workflow runs for any `owner/repo`
- Enriches runs with failed jobs/steps details
- Pulls failed logs and classifies likely failure type:
  - `test_failure`
  - `lint_or_typecheck`
  - `dependency_or_build`
  - `infra_or_flaky`
  - `auth_or_secrets`
  - `unknown`
- Provides:
  - likely failure reason
  - fail-point hotspots (`job -> step`)
  - confidence score
  - severity (`high`, `medium`, `low`) with badges
  - short failed-log excerpt
- Supports sorting and filtering by severity
- Quick actions:
  - open top 3 high-severity runs
  - export visible summary to `.txt`
  - auto-refresh every 30s

## Requirements
- Node.js 18+
- GitHub CLI (`gh`) authenticated with access to target repos
- OpenClaw installed on host

## TLS / HTTPS Hardening (Node.js direct)

This project now runs HTTPS by default with:

- `minVersion: TLSv1.2`
- TLS 1.2 cipher allowlist:
  - `ECDHE-ECDSA-AES128-GCM-SHA256`
  - `ECDHE-RSA-AES128-GCM-SHA256`
  - `ECDHE-ECDSA-AES256-GCM-SHA384`
  - `ECDHE-RSA-AES256-GCM-SHA384`
- HTTP (`:80`) → HTTPS (`:443`) redirect with `301`
- HSTS header:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- Outbound TLS verification enabled (`rejectUnauthorized: true`)
- Optional certificate pinning via `TLS_PINNED_SPKI_SHA256`
- Strict dynamic CORS whitelist (no wildcard)

### CORS environment configuration

```bash
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
ALLOWED_METHODS=GET,POST,OPTIONS
ALLOWED_HEADERS=Authorization,Content-Type
```

### IP allowlists and webhook validation

```bash
ADMIN_ALLOWED_IPS=203.0.113.10,10.8.0.0/24,2001:db8::/48
WEBHOOK_ALLOWED_IPS=198.51.100.0/24,2001:db8:feed::/48
WEBHOOK_HMAC_SECRET=replace-with-strong-secret
```

### Cost circuit breaker configuration

```bash
CIRCUIT_BREAKER_WEBHOOK=https://hooks.slack.com/services/xxx
CIRCUIT_BREAKER_EMAIL=admin@yourdomain.com
CIRCUIT_BREAKER_WARNING=100
CIRCUIT_BREAKER_SOFT=250
CIRCUIT_BREAKER_HARD=500
CIRCUIT_BREAKER_EMERGENCY=1000
REDIS_URL=redis://127.0.0.1:6379
RATE_LIMIT_REDIS_PREFIX=aod:rl:
```

### Prompt injection defense configuration

```bash
# Optional monitoring bypass for health/observability
INTERNAL_MONITORING_IPS=10.0.0.10
INTERNAL_MONITORING_HEADER=x-internal-monitoring
INTERNAL_MONITORING_HEADER_VALUE=allow
```

Built-in protections on `/api/models/invoke`:
- Input limits: max 4000 chars, 50 turns, 2000-char system prompt
- Hard-block jailbreak patterns
- Sanitizes script/SQL/path traversal sequences
- Quarantine API key after repeated blocked attempts
- Output redaction for key/PII/system-prompt leakage
- Canary token leak detection and alert logging

Admin endpoints:
- `GET /admin/costs`
- `POST /admin/costs/reset` (owner only)
- `PUT /admin/costs/limits` (owner only)
- `GET /admin/logs` (admin/owner; filter by `category`, `level`, `since`, `until`, `q`)
- `GET /admin/logs/digest` (daily medium-severity summaries)

### Structured security logging

JSON log schema:
- `timestamp` (ISO 8601)
- `level` (`info|warn|error|critical`)
- `category` (`auth|api|model|admin|security`)
- `event`
- `metadata` (masked identifiers)
- `request_id`

Sensitive data is not logged (passwords/full tokens/full API keys/prompt content).

Environment:
```bash
LOG_DIR=/path/to/logs
LOG_FORWARD_URL=https://logs.example.com/ingest
ADMIN_RECOGNIZED_IPS=203.0.113.10,10.8.0.0/24
```

### Alert rules

Critical (immediate):
- 10+ failed logins from same IP in 5 min
- circuit breaker emergency
- unknown API key usage
- admin action from unrecognized IP

High:
- 5+ prompt injection attempts from same key
- cost spike >3x normal hourly
- error rate >10% over 5 min

Medium (daily digest):
- rate limit summary by key/IP
- failed auth summary
- cost summary by model/key (`/admin/logs/digest`)

### Log rotation

Script: `scripts/log-rotate.sh`
- rotate daily
- compress logs older than 1 day
- retain security logs 365 days
- retain general logs 30 days

LaunchAgent installed:
- `~/Library/LaunchAgents/com.assistant-ops-dashboard.log-rotate.plist`
- runs daily at 00:05

- Admin IP allowlist applies to `/admin/*` and `/api/v1/admin/*`
- Webhooks require both source IP allowlist match and `x-webhook-signature` HMAC-SHA256 validation
- In production, `/docs`, `/swagger`, `/api-docs`, `/debug/*`, and `/test/*` are blocked

Behavior:
- Returns a matched origin (never `*`)
- Returns no CORS headers for unmatched origins
- Logs rejected origins as `[cors-rejected] ...`
- Caches preflight for 24h (`Access-Control-Max-Age: 86400`)

### Local dev run (non-root ports)

```bash
npm install
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout certs/privkey.pem \
  -out certs/fullchain.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

HTTPS_PORT=3443 HTTP_PORT=3080 npm start
```

Then open:

- `https://localhost:3443/login`

## Screenshot

> Add a screenshot at `docs/screenshot.png` and it will render automatically.

![Dashboard Screenshot](docs/screenshot.png)

## Demo Script (60–90s)

1. Enter `owner/repo`, click **Load failures**
2. Show that failures are sorted with high severity first
3. Set **Severity = High** to filter
4. Expand a **Failed log excerpt**
5. Click **Open top 3 high severity**
6. Click **Export summary** and show downloaded file
7. Toggle **Auto-refresh** (30s)

## Automatic certificate renewal (certbot)

Installed and configured with a LaunchAgent:

- `~/Library/LaunchAgents/com.assistant-ops-dashboard.certbot-renew.plist`
- Script: `scripts/certbot-renew.sh`
- Schedule: daily at 03:17 local time

Dry-run test command:

```bash
certbot renew --dry-run \
  --config-dir ~/.assistant-ops-dashboard/certbot/config \
  --work-dir ~/.assistant-ops-dashboard/certbot/work \
  --logs-dir ~/.assistant-ops-dashboard/certbot/logs
```

## API Endpoints (high level)
- `GET /api/health` — OpenClaw status
- `POST /api/restart` — restart gateway
- `GET /api/ci/failures?repo=owner/repo&limit=5` — CI failed run summaries

## Roadmap
- [x] CI failed run summarization (workflow + run metadata)
- [x] Failed jobs/steps enrichment
- [x] Log-based failure classification + quick fix hints
- [x] Confidence scoring + severity badges
- [x] Severity filter/sort + quick triage actions
- [ ] Screenshot + GIF walkthrough
- [ ] PR comment bot mode (post summary to pull requests)
- [ ] Slack/Discord notifier for high-severity CI failures

## Notes
- This dashboard relies on `gh` command output; make sure you are logged in (`gh auth status`).
- Failure classification is heuristic-based and intended as triage assistance, not a root-cause guarantee.
