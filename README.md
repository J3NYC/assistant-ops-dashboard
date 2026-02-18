# Assistant Ops Dashboard

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

## Run Locally

```bash
npm install
npm start
```

Then open:

- `http://localhost:3000`

## Demo Script (60–90s)

1. Enter `owner/repo`, click **Load failures**
2. Show that failures are sorted with high severity first
3. Set **Severity = High** to filter
4. Expand a **Failed log excerpt**
5. Click **Open top 3 high severity**
6. Click **Export summary** and show downloaded file
7. Toggle **Auto-refresh** (30s)

## API Endpoints (high level)
- `GET /api/health` — OpenClaw status
- `POST /api/restart` — restart gateway
- `GET /api/ci/failures?repo=owner/repo&limit=5` — CI failed run summaries

## Notes
- This dashboard relies on `gh` command output; make sure you are logged in (`gh auth status`).
- Failure classification is heuristic-based and intended as triage assistance, not a root-cause guarantee.
