# Observability & Operations

## Metrics

SentinelCore exposes Prometheus metrics on the metrics port (default `:9090`
via `METRICS_PORT` env var) at `/metrics`.

### Available metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `sentinelcore_scan_created_total` | counter | scan_type, trigger_type | Scans created |
| `sentinelcore_scan_completed_total` | counter | scan_type, status | Scans completed/failed |
| `sentinelcore_scan_duration_seconds` | histogram | scan_type | Scan execution time |
| `sentinelcore_findings_per_scan` | histogram | scan_type | Findings produced per scan |
| `sentinelcore_worker_jobs_processed_total` | counter | worker_type, status | Worker job completions |
| `sentinelcore_worker_queue_latency_seconds` | histogram | worker_type | Time from creation to pickup |
| `sentinelcore_export_requests_total` | counter | format, scope | Export endpoint usage |
| `sentinelcore_webhook_deliveries_total` | counter | event, status | Webhook delivery attempts |
| `sentinelcore_webhook_delivery_seconds` | histogram | event | Webhook delivery latency |
| `sentinelcore_apikey_auth_total` | counter | status | API key auth attempts |
| `sentinelcore_http_requests_total` | counter | method, path, status | HTTP request counts |
| `sentinelcore_http_request_duration_seconds` | histogram | method, path | HTTP latency |

### Scrape configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: sentinelcore
    static_configs:
      - targets: ['sentinelcore-api:9090']
```

## Operational endpoints

### Queue status
`GET /api/v1/ops/queue` (requires `system.config` permission)

Returns scan job counts by status and the 10 most recent jobs:
```json
{
  "queue_status": [
    {"status": "pending", "count": 2},
    {"status": "completed", "count": 15}
  ],
  "recent_jobs": [
    {"id": "...", "scan_type": "sast", "status": "completed", "created_at": "...", "duration": "3s"}
  ]
}
```

### Webhook status
`GET /api/v1/ops/webhooks` (requires `system.config` permission)

Returns configured webhooks with redacted URLs:
```json
{
  "webhooks": [
    {"id": "...", "name": "CI", "url_prefix": "https://hooks.example.com/…", "enabled": true, "events": ["scan.completed"]}
  ]
}
```

## Health checks

| Endpoint | Port | Purpose |
|---|---|---|
| `GET /healthz` | 8080 | Liveness probe |
| `GET /readyz` | 8080 | Readiness probe (DB + Redis + NATS) |

## Troubleshooting

### "Scans are not being processed"
1. Check `GET /api/v1/ops/queue` — are jobs stuck in `pending`?
2. Check SAST worker logs: `docker logs sentinelcore_sast_worker`
3. Verify NATS connectivity: `GET /readyz` should show `nats: ok`
4. Check `sentinelcore_worker_jobs_processed_total` metric

### "Webhooks are not firing"
1. Check `GET /api/v1/ops/webhooks` — is the webhook enabled and subscribed to `scan.completed`?
2. Check `sentinelcore_webhook_deliveries_total{status="error"}` metric
3. Check controlplane logs for "webhook delivery failed" warnings
4. Verify the webhook URL is reachable from the SentinelCore network

### "Exports are slow"
1. Check `sentinelcore_export_requests_total` for volume
2. Check scan-level exports — they fetch all findings, which may be slow for large scans
3. Consider limiting `?limit=` on the findings query if needed

### "API key rejected"
1. Check `sentinelcore_apikey_auth_total{status="failed"}` metric
2. Verify the key prefix matches an active key: `GET /api/v1/api-keys`
3. Check key expiration and revocation status
