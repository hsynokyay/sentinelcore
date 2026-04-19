# SentinelCore Configuration Reference

All SentinelCore services are configured via environment variables.

## Control Plane (`cmd/controlplane`)

### Database

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `DB_HOST` | `localhost` | No | PostgreSQL hostname |
| `DB_PORT` | `5432` | No | PostgreSQL port |
| `DB_NAME` | `sentinelcore` | No | Database name |
| `DB_USER` | `sentinelcore` | No | Database user |
| `DB_PASSWORD` | `dev-password` | **Yes (production)** | Database password |
| `DB_MAX_CONNS` | `20` | No | Connection pool max size |

### Redis

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `REDIS_URL` | `redis://localhost:6379` | No | Redis connection URL |

### NATS

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `NATS_URL` | `nats://localhost:4222` | No | NATS server URL |

### Server

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `PORT` | `8080` | No | HTTP API listen port |
| `METRICS_PORT` | `9090` | No | Prometheus metrics port |

### Authentication

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `JWT_PRIVATE_KEY_FILE` | _(auto-generated)_ | No | Path to RSA private key PEM. If unset, a dev key pair is generated on startup. |
| `JWT_PUBLIC_KEY_FILE` | _(auto-generated)_ | No | Path to RSA public key PEM. Must be set together with private key. |

### Security

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `CORS_ORIGIN` | `http://localhost:3000` | No | Comma-separated allowed origins for CORS. Must be explicit (no wildcards with credentials). |
| `FORCE_SECURE_COOKIES` | _(empty)_ | **Yes (production)** | Set to `true` to unconditionally set `Secure` flag on all cookies. Required when TLS terminates at a load balancer. |
| `TRUST_PROXY_HEADERS` | _(empty)_ | No | Set to `true` to trust `X-Forwarded-Proto` header for Secure cookie decisions. **Only safe behind a reverse proxy that strips and re-sets this header.** |

## DAST Worker (`cmd/dast-worker`)

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `NATS_URL` | `nats://localhost:4222` | No | NATS server URL |
| `CONCURRENCY` | `10` | No | Maximum parallel test case execution |
| `REQUEST_TIMEOUT` | `30s` | No | Per-request timeout (Go duration format) |
| `MSG_SIGNING_KEY` | _(none)_ | **Yes** | HMAC signing key for NATS messages. Fatal if empty. |
| `WORKER_ID` | _(auto-generated)_ | No | Worker identifier for tracing |

## Browser DAST Worker (`cmd/dast-browser-worker`)

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `NATS_URL` | `nats://localhost:4222` | No | NATS server URL |
| `MSG_SIGNING_KEY` | _(none)_ | **Yes** | HMAC signing key for NATS messages |
| `MAX_URLS` | `500` | No | Maximum URLs per browser crawl |
| `MAX_DEPTH` | `3` | No | Maximum crawl depth |
| `SCAN_TIMEOUT` | `30m` | No | Maximum scan wall-clock time |

## Auth Session Broker (`cmd/auth-broker`)

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `NATS_URL` | `nats://localhost:4222` | No | NATS server URL |

## Retention Worker (`cmd/retention-worker`)

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `DATABASE_URL` | `postgres://sentinel:sentinel@localhost:5432/sentinel?sslmode=disable` | No | PostgreSQL connection string |
| `NATS_URL` | `nats://localhost:4222` | No | NATS server URL |
| `RETENTION_INTERVAL` | `3600` | No | Retention cycle interval in seconds |

## Notification Worker (`cmd/notification-worker`)

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `DATABASE_URL` | `postgres://sentinel:sentinel@localhost:5432/sentinel?sslmode=disable` | No | PostgreSQL connection string |
| `NATS_URL` | `nats://localhost:4222` | No | NATS server URL |
| `WEBHOOK_DELIVERY_INTERVAL` | `30` | No | Webhook delivery poll interval in seconds |

## Correlation Engine (`cmd/correlation-engine`)

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `NATS_URL` | `nats://localhost:4222` | No | NATS server URL |
| `MSG_SIGNING_KEY` | _(none)_ | **Yes** | HMAC signing key for NATS messages |

## Frontend (`web/`)

| Variable | Default | Required | Description |
|----------|---------|:--------:|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | No | Backend API base URL |
| `NEXT_PUBLIC_DEMO_MODE` | _(empty)_ | No | Set to `true` to bypass auth for UI preview |

## Production Checklist

- [ ] Set `DB_PASSWORD` to a strong, unique password
- [ ] Set `JWT_PRIVATE_KEY_FILE` and `JWT_PUBLIC_KEY_FILE` (do not use auto-generated dev keys)
- [ ] Set `MSG_SIGNING_KEY` to a strong random string (at least 32 bytes)
- [ ] Set `FORCE_SECURE_COOKIES=true`
- [ ] Set `CORS_ORIGIN` to your frontend domain (e.g., `https://sentinel.yourcompany.com`)
- [ ] Do NOT set `TRUST_PROXY_HEADERS=true` unless behind a stripping proxy
- [ ] Set `NEXT_PUBLIC_API_URL` to your backend URL
- [ ] Remove `NEXT_PUBLIC_DEMO_MODE` or set to empty
