# SentinelCore Phase 1 Quick Start

## Prerequisites
- Go 1.22+
- Docker & Docker Compose
- git

## Build
```bash
make build
```

## Start Infrastructure
```bash
make docker-up
```

## Run Migrations
```bash
export DATABASE_URL="postgres://sentinelcore:dev-password@localhost:5432/sentinelcore?sslmode=disable"
make migrate-up
```

## Bootstrap
```bash
./bin/cli bootstrap --admin-email admin@local --admin-password changeme
```

## Start Services (development mode — run each in a separate terminal)
```bash
./bin/policy-engine
./bin/audit-service
./bin/controlplane
./bin/sast-worker
./bin/vuln-intel
./bin/updater
```

## Run Tests
```bash
# Unit tests (no infra required)
go test ./internal/... ./pkg/crypto/... -count=1

# Acceptance test (requires running services)
./scripts/acceptance-test.sh
```

## Key Endpoints
- `POST /api/v1/auth/login` — Get JWT
- `GET /api/v1/projects` — List projects
- `POST /api/v1/projects/{id}/scans` — Trigger scan
- `GET /api/v1/findings` — Query findings
- `GET /healthz` — Health check
