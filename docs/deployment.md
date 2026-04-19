# SentinelCore Deployment Guide

## Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| PostgreSQL | 16+ | Primary data store |
| Redis | 7+ | Session store, caching |
| NATS | 2.10+ (with JetStream) | Inter-service messaging |
| Go | 1.22+ | Build backend services |
| Node.js | 18+ | Build and run frontend |
| Docker + Compose | Latest | Container orchestration (recommended) |

## Docker Compose Quickstart

The fastest path to a running instance:

```bash
cd deploy/docker-compose
docker compose up --build -d
```

This starts all infrastructure (PostgreSQL 16, NATS 2.10 with JetStream, Redis 7, MinIO) and application services (controlplane, policy-engine, audit-service, dast-worker, dast-browser-worker, sast-worker, vuln-intel, correlation-engine, retention-worker, notification-worker, auth-broker, updater).

The controlplane API is available at `http://localhost:8080`. NATS monitoring is at `http://localhost:8222`.

To stop:

```bash
docker compose down        # keep volumes
docker compose down -v     # destroy volumes (full reset)
```

## Database Migrations

Migrations live in `migrations/` as numbered `.up.sql` and `.down.sql` pairs (001 through 015).

### Manual Application (current)

```bash
# Connect to your PostgreSQL instance
export PGHOST=localhost PGPORT=5432 PGDATABASE=sentinelcore PGUSER=sentinelcore

# Apply migrations in order
for f in migrations/0*_*.up.sql; do
  echo "Applying $f ..."
  psql -f "$f"
done
```

### Future: Automatic Migration

Set `AUTO_MIGRATE=true` on the controlplane to run pending migrations at startup (not yet implemented; planned for a future release).

### Rollback

Apply the corresponding `.down.sql` file in reverse order:

```bash
psql -f migrations/015_surface_inventory.down.sql
```

## Seed Data

Load demo data for evaluation or development:

```bash
psql -h localhost -U sentinelcore -d sentinelcore -f scripts/seed.sql
```

The seed script is idempotent (uses `INSERT ... ON CONFLICT DO NOTHING`) and creates:

| User | Role | Password |
|------|------|----------|
| `admin` | platform_admin | `SentinelDemo1!` |
| `secadmin` | security_admin | `SentinelDemo1!` |
| `analyst` | analyst | `SentinelDemo1!` |
| `auditor` | auditor | `SentinelDemo1!` |

It also creates a demo organization, two teams (Platform Security, Application Security), sample targets, scan configurations, and policies.

**Do not use seed data in production.** Create users through the API or a dedicated provisioning script with unique credentials.

## Frontend Deployment

```bash
cd web
npm install
NEXT_PUBLIC_API_URL=https://api.sentinel.yourcompany.com npm run build
npm start
```

The frontend listens on port 3000 by default. Set `NEXT_PUBLIC_API_URL` at build time to point to the backend.

For production, serve the built output behind a reverse proxy or use `next start` with a process manager (pm2, systemd).

## TLS Configuration

SentinelCore does not terminate TLS itself. Use a reverse proxy.

### Nginx Example

```nginx
server {
    listen 443 ssl;
    server_name sentinel.yourcompany.com;

    ssl_certificate     /etc/ssl/certs/sentinel.pem;
    ssl_certificate_key /etc/ssl/private/sentinel.key;

    # API
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
    }

    # Frontend
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
}
```

### Caddy Example

```
sentinel.yourcompany.com {
    handle /api/* {
        reverse_proxy localhost:8080
    }
    handle {
        reverse_proxy localhost:3000
    }
}
```

Set these environment variables on the controlplane when behind TLS:

```
FORCE_SECURE_COOKIES=true
TRUST_PROXY_HEADERS=true
```

`TRUST_PROXY_HEADERS` should only be enabled when the reverse proxy strips and re-sets `X-Forwarded-Proto`.

## CORS

Set `CORS_ORIGIN` on the controlplane to the exact frontend origin:

```
CORS_ORIGIN=https://sentinel.yourcompany.com
```

Multiple origins can be comma-separated. Wildcards are not supported when credentials are in use.

## Verification

After deployment, verify all components:

```bash
# Liveness (is the process running?)
curl -sf http://localhost:8080/healthz
# Expected: 200 OK

# Readiness (are dependencies connected?)
curl -sf http://localhost:8080/readyz
# Expected: 200 OK with component status JSON

# Login test
curl -sf -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"SentinelDemo1!"}'
# Expected: 200 with session token (seed data must be loaded)

# Metrics endpoint
curl -sf http://localhost:9090/metrics | head -5
# Expected: Prometheus-format metrics
```

## Production Checklist

Before going live, complete every item in the [Configuration Reference production checklist](configuration.md#production-checklist):

- [ ] Set `DB_PASSWORD` to a strong, unique password
- [ ] Provide RSA key pair via `JWT_PRIVATE_KEY_FILE` and `JWT_PUBLIC_KEY_FILE`
- [ ] Set `MSG_SIGNING_KEY` to a random string of at least 32 bytes
- [ ] Set `FORCE_SECURE_COOKIES=true`
- [ ] Set `CORS_ORIGIN` to the production frontend domain
- [ ] Disable `TRUST_PROXY_HEADERS` unless behind a stripping proxy
- [ ] Set `NEXT_PUBLIC_API_URL` to the production backend URL
- [ ] Remove or unset `NEXT_PUBLIC_DEMO_MODE`
- [ ] Run all migrations against the production database
- [ ] Verify `/healthz` and `/readyz` return 200
- [ ] Confirm TLS is enforced end-to-end
- [ ] Review [secrets management](secrets.md) for key provisioning
