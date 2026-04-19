# SentinelCore Operations Guide

## Backup

### PostgreSQL

Daily logical backup with `pg_dump`:

```bash
pg_dump -Fc -h localhost -U sentinelcore -d sentinelcore \
  > /backup/sentinelcore-$(date +%Y%m%d).dump
```

Use `-Fc` (custom format) for parallel restore support. Retain at least 7 daily backups and 4 weekly backups.

For large databases, use `pg_dump --jobs=4` for parallel dump.

### Redis

Redis is configured with RDB snapshots by default. Copy the dump file:

```bash
redis-cli -h localhost BGSAVE
cp /var/lib/redis/dump.rdb /backup/redis-$(date +%Y%m%d).rdb
```

Redis stores sessions and cache data. Loss of Redis data causes active sessions to expire (users must re-login) but does not cause data loss.

### Artifact Storage

If using local artifact storage, back up the artifact directory:

```bash
tar czf /backup/artifacts-$(date +%Y%m%d).tar.gz /var/lib/sentinelcore/artifacts/
```

If using MinIO or S3, ensure bucket versioning or cross-region replication is enabled.

## Restore

### PostgreSQL

```bash
pg_restore -h localhost -U sentinelcore -d sentinelcore \
  --clean --if-exists /backup/sentinelcore-20260401.dump
```

### Redis

```bash
# Stop Redis, replace dump, restart
systemctl stop redis
cp /backup/redis-20260401.rdb /var/lib/redis/dump.rdb
systemctl start redis
```

### Artifacts

```bash
tar xzf /backup/artifacts-20260401.tar.gz -C /
```

## Database Maintenance

### VACUUM ANALYZE

Run weekly to reclaim dead rows and update planner statistics:

```bash
psql -h localhost -U sentinelcore -d sentinelcore \
  -c "VACUUM ANALYZE;"
```

For large tables (findings, audit_events), consider targeted vacuum during low-traffic windows:

```sql
VACUUM ANALYZE findings.findings;
VACUUM ANALYZE audit.audit_events;
```

### Index Monitoring

Check for unused or bloated indexes:

```sql
-- Unused indexes (candidates for removal)
SELECT schemaname, relname, indexrelname, idx_scan
FROM pg_stat_user_indexes
WHERE idx_scan = 0
ORDER BY pg_relation_size(indexrelid) DESC;

-- Index bloat estimation
SELECT schemaname, tablename, indexname,
       pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
ORDER BY pg_relation_size(indexrelid) DESC
LIMIT 20;
```

## Log Management

### Format

All backend services use zerolog and emit structured JSON to stdout:

```json
{"level":"info","service":"controlplane","ts":"2026-04-03T10:00:00Z","msg":"request completed","method":"GET","path":"/api/v1/scans","status":200,"latency_ms":12}
```

### Log Level

Set via the `LOG_LEVEL` environment variable on each service. Values: `debug`, `info`, `warn`, `error`. Default is `info`.

### Rotation

SentinelCore does not handle log rotation. Use an external mechanism:

- **Docker**: Docker's built-in log driver with `max-size` and `max-file` options
- **systemd**: journald handles rotation automatically
- **Files**: logrotate with daily rotation and 30-day retention

## Emergency Stop

The emergency stop feature halts all active scans and prevents new scan submissions.

### Activate via API

```bash
curl -X POST http://localhost:8080/api/v1/admin/emergency-stop \
  -H 'Authorization: Bearer <admin-token>' \
  -H 'Content-Type: application/json' \
  -d '{"reason": "Suspected false positive flood"}'
```

### Lift via API

```bash
curl -X DELETE http://localhost:8080/api/v1/admin/emergency-stop \
  -H 'Authorization: Bearer <admin-token>'
```

Emergency stop can also be activated and lifted from the Admin panel in the UI under Settings > Emergency Controls.

## Key Rotation

### JWT Keys

1. Generate a new RSA key pair:
   ```bash
   openssl genrsa -out jwt-new.key 4096
   openssl rsa -in jwt-new.key -pubout -o jwt-new.pub
   ```
2. Deploy new key files to the controlplane (`JWT_PRIVATE_KEY_FILE`, `JWT_PUBLIC_KEY_FILE`).
3. Restart the controlplane. Existing tokens signed with the old key will fail validation and expire naturally (default TTL: 15 minutes).
4. Users with expired tokens are prompted to re-login.

### MSG_SIGNING_KEY

1. Set the new key value in the environment for **all** services that use it (controlplane, dast-worker, dast-browser-worker, sast-worker, correlation-engine).
2. Restart all affected services simultaneously. Messages signed with the old key will be rejected.
3. Any in-flight NATS messages signed with the old key will fail and be retried by their producers.

### Encryption Keys

`AUTH_PROFILE_ENCRYPTION_KEY` encrypts stored authentication profiles. Rotation requires re-encrypting existing records. A future release will support key versioning via a `key_id` column; until then, rotation requires a manual re-encryption migration.

## Scaling

### Workers

Scale DAST and SAST workers horizontally by increasing replicas:

```bash
# Docker Compose
docker compose up -d --scale dast-worker=4 --scale sast-worker=3
```

Each worker instance connects to NATS and consumes from a shared queue group. No additional configuration is needed.

### Database Connection Pool

Increase `DB_MAX_CONNS` on the controlplane proportionally to load. Default is 20. A good starting point is 5 connections per expected concurrent API request. Monitor `pg_stat_activity` for connection pressure:

```sql
SELECT count(*), state FROM pg_stat_activity
WHERE datname = 'sentinelcore' GROUP BY state;
```

Consider PgBouncer for connection pooling at scale (100+ connections).

### NATS

NATS JetStream handles message persistence. For high-throughput environments, deploy a 3-node NATS cluster for fault tolerance.

## Monitoring

### Prometheus Metrics

The controlplane exposes Prometheus metrics on port 9090 (configurable via `METRICS_PORT`):

```
http://localhost:9090/metrics
```

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `http_request_duration_seconds` | API request latency histogram | p99 > 2s |
| `http_requests_total` | Request count by method, path, status | 5xx rate > 1% |
| `nats_messages_pending` | Messages awaiting processing | > 1000 sustained |
| `scan_queue_depth` | Scans waiting for workers | > 50 sustained |
| `db_connections_in_use` | Active database connections | > 80% of max |
| `go_goroutines` | Active goroutines | > 10000 |

### Grafana

Import the Prometheus metrics into Grafana. No pre-built dashboards are shipped; create panels for the key metrics above.

## Troubleshooting

### Common Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `401 session revoked` | Session was invalidated (admin action or key rotation) | Re-login to obtain a new session |
| `403 CSRF validation failed` | CSRF token mismatch, often a cookie issue | Clear cookies and re-login. Verify `CORS_ORIGIN` matches the frontend domain and `FORCE_SECURE_COOKIES` is set correctly for the TLS configuration |
| `429 rate limit exceeded` | Too many requests from this client | Wait for the `Retry-After` header duration, then retry |
| `503 service unhealthy` | One or more dependencies are down | Check `/readyz` for component-level status. Verify PostgreSQL, Redis, and NATS are reachable |
| `NATS: message signature invalid` | `MSG_SIGNING_KEY` mismatch between services | Ensure all services share the same `MSG_SIGNING_KEY` value and restart |
| `connection refused` on port 8080 | Controlplane not running or not listening | Check container/process status. Review logs for startup errors |

### Dependency Checks

```bash
# PostgreSQL
pg_isready -h localhost -U sentinelcore

# Redis
redis-cli -h localhost ping

# NATS
curl -sf http://localhost:8222/healthz
```

## Health Checks

### /healthz (Liveness)

Returns `200 OK` if the controlplane process is running. Use for container orchestrator liveness probes.

```bash
curl -sf http://localhost:8080/healthz
```

Failure means the process is hung or crashed. Restart the container.

### /readyz (Readiness)

Returns `200 OK` with a JSON body indicating the status of each dependency:

```json
{
  "status": "ok",
  "components": {
    "postgres": "ok",
    "redis": "ok",
    "nats": "ok"
  }
}
```

If any component is degraded, the overall status changes to `degraded` and the HTTP status is `503`. Use for load balancer health checks to drain traffic from unhealthy instances.

```bash
# Check readiness with component detail
curl -sf http://localhost:8080/readyz | jq .
```
