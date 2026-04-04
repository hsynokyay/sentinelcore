# SentinelCore Local Bring-Up

Run SentinelCore locally with real demo data in 2 commands.

## Prerequisites

- macOS with Homebrew installed
- Go 1.22+
- Node.js 18+ (for frontend)

## Two-Command Start

**Terminal 1 — infrastructure + backend:**
```bash
./scripts/local-bringup.sh
```

This installs (if missing) and starts PostgreSQL 16, Redis, NATS. Runs migrations. Seeds demo data. Starts the control plane on `:8080`.

**Terminal 2 — frontend:**
```bash
cd web
npm install
node_modules/.bin/next dev --webpack
```

Then open **http://localhost:3000**.

## Demo Credentials

| Email | Password | Role |
|-------|----------|------|
| admin@sentinel.io | SentinelDemo1! | platform_admin |
| secadmin@sentinel.io | SentinelDemo1! | security_admin |
| analyst@sentinel.io | SentinelDemo1! | appsec_analyst |
| auditor@sentinel.io | SentinelDemo1! | auditor |

## What Works End-to-End

| Page | Data |
|------|------|
| Login | Real JWT auth flow |
| Findings | 25 findings across all severities, types, statuses |
| Scans | 3 completed scans (SAST, DAST, DAST) |
| Attack Surface | 5 entries (routes, forms, API endpoint) |
| Approvals | 2 approval requests (1 pending, 1 approved) |
| Notifications | 5 notifications for admin user |
| Audit Log | 10 audit events (login, scan, triage, approval, emergency stop) |
| Settings | Governance configuration |

## Stopping

```bash
./scripts/local-teardown.sh
```

Stops backend, frontend, and NATS. Keeps PostgreSQL and Redis running (preserves data).

To fully stop:
```bash
brew services stop postgresql@16
brew services stop redis
```

## Troubleshooting

**Login fails with "invalid credentials":**
The seed script stores a pre-computed bcrypt hash that's re-set by `local-bringup.sh`. If you reset the database manually, re-run the script.

**"user not found" after login:**
The backend queries `users.me` and RLS needs the user row to exist. Verify:
```bash
psql -U sentinelcore -d sentinelcore -c "SELECT email, role FROM core.users;"
```

**Findings page shows 0 results:**
Check backend logs for SQL errors:
```bash
tail -20 /tmp/sentinelcore-api.log
```

**Port conflicts:**
- 8080: backend API
- 9090: metrics
- 3000: frontend
- 5432: PostgreSQL
- 6379: Redis
- 4222: NATS

Free a port: `lsof -ti:8080 | xargs kill`

## Architecture (local)

```
http://localhost:3000 (Next.js)
         ↓
http://localhost:8080 (Go control plane)
         ↓
PostgreSQL (5432) + Redis (6379) + NATS (4222)
```

All services run as local processes via Homebrew. No Docker required.
