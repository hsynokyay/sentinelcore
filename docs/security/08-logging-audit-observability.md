# 8. Logging, Audit, and Observability

## 8.1 Three-Pillar Observability

SentinelCore implements structured observability across logs, metrics, and traces using OpenTelemetry as the standard instrumentation layer.

### 8.1.1 Architecture

```
┌───────────────────────────────────────────────────────────────┐
│ Services (all SentinelCore components)                        │
│  ├── Structured JSON Logs → OpenTelemetry Collector → Loki   │
│  ├── Metrics (Prometheus) → Prometheus → Grafana              │
│  └── Traces (OTLP)       → OpenTelemetry Collector → Tempo   │
└───────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────┐
│ Audit Log Service                                             │
│  └── Append-Only Audit Events → PostgreSQL (audit schema)     │
│                                → SIEM Export (optional)       │
└───────────────────────────────────────────────────────────────┘
```

## 8.2 Application Logging

### 8.2.1 Log Format

All services produce structured JSON logs:

```json
{
  "timestamp": "2026-03-14T10:30:00.123Z",
  "level": "info",
  "logger": "sentinelcore.orchestrator",
  "message": "Scan job dispatched",
  "trace_id": "abc123def456",
  "span_id": "789ghi",
  "service": "scan-orchestrator",
  "version": "1.2.0",
  "fields": {
    "scan_id": "uuid-here",
    "project_id": "uuid-here",
    "scan_type": "dast",
    "worker_id": "dast-worker-3"
  }
}
```

### 8.2.2 Log Levels

| Level | Usage |
|---|---|
| ERROR | Unrecoverable failures requiring operator attention |
| WARN | Degraded state, retryable failures, approaching limits |
| INFO | Significant state transitions (scan started, completed, etc.) |
| DEBUG | Detailed operational information (disabled in production by default) |

### 8.2.3 Log Sanitization

- **Credentials:** NEVER logged. Credential fields are redacted at the logger level.
- **PII:** User emails and display names are logged only in audit events, not application logs.
- **Request bodies:** DAST HTTP traces are logged to evidence store, not to application logs.
- **Stack traces:** Included for ERROR level only, with source paths normalized.

### 8.2.4 Log Collection

| Environment | Collection Method |
|---|---|
| Kubernetes | stdout → Fluentd/Fluent Bit DaemonSet → Loki |
| Docker Compose | stdout → Promtail → Loki |
| External SIEM | Fluentd output plugin → syslog/HTTPS/Kafka |

## 8.3 Audit Log System

### 8.3.1 Design Requirements

The audit log system is the compliance backbone of SentinelCore. It must be:

1. **Complete** — Every state-changing action produces an audit entry
2. **Immutable** — Entries cannot be modified or deleted (append-only)
3. **Tamper-evident** — Integrity chain detects any manipulation
4. **Queryable** — Supports efficient search by actor, resource, action, time range
5. **Exportable** — Standard formats for SIEM and compliance tools

### 8.3.2 Audit Event Schema

```json
{
  "event_id": "uuid",
  "timestamp": "2026-03-14T10:30:00.123Z",
  "actor": {
    "type": "user",
    "id": "uuid",
    "username": "jdoe",
    "ip_address": "10.0.1.50",
    "user_agent": "sentinelcore-cli/1.2.0"
  },
  "action": "scan.created",
  "resource": {
    "type": "scan_job",
    "id": "uuid",
    "project_id": "uuid"
  },
  "context": {
    "org_id": "uuid",
    "team_id": "uuid",
    "request_id": "uuid",
    "trace_id": "abc123"
  },
  "details": {
    "scan_type": "dast",
    "scan_target": "https://app.example.com",
    "scan_profile": "standard"
  },
  "result": "success",
  "integrity": {
    "previous_hash": "sha256:abc...",
    "entry_hash": "sha256:def..."
  }
}
```

### 8.3.3 Audited Actions

| Category | Actions |
|---|---|
| Authentication | login, logout, login_failed, token_created, token_revoked |
| Authorization | permission_granted, permission_revoked, role_changed, access_denied |
| Project Management | project.created, project.updated, project.archived, project.deleted |
| Scan Lifecycle | scan.created, scan.started, scan.completed, scan.failed, scan.cancelled |
| Scan Scope | scope.created, scope.modified, scope.verified |
| Finding Triage | finding.triaged, finding.annotated, finding.status_changed |
| Policy | policy.created, policy.updated, policy.assigned, policy.evaluated |
| Rules | rule.imported, rule.updated, rule.disabled |
| Updates | update.downloaded, update.verified, update.applied, update.rolled_back |
| Credentials | credential.created, credential.accessed, credential.rotated, credential.deleted |
| Configuration | config.changed (with before/after diff) |
| Data Export | report.generated, data.exported, evidence.accessed |
| System | system.startup, system.shutdown, backup.created, backup.restored |

### 8.3.4 Integrity Chain

Each audit log entry includes an HMAC-SHA256 chain:

```
Entry N:
  previous_hash = HMAC-SHA256(key, Entry N-1 serialized)
  entry_hash    = HMAC-SHA256(key, Entry N serialized including previous_hash)

Entry N+1:
  previous_hash = entry_hash of Entry N
  entry_hash    = HMAC-SHA256(key, Entry N+1 serialized including previous_hash)
```

- HMAC key is stored in Vault and rotated quarterly
- A background integrity verification job runs hourly
- Integrity violations trigger alerts via webhook

### 8.3.5 Audit Log Access Control

- Only the Audit Log Service can write to audit tables
- Database user for audit has INSERT-only permissions (no UPDATE, DELETE)
- Admin users can read audit logs but cannot modify them
- Audit log retention is enforced via partition dropping (configurable, minimum 1 year)
- Archived partitions are exported to encrypted files before dropping

### 8.3.6 SIEM Integration

| Method | Protocol | Details |
|---|---|---|
| Syslog | RFC 5424 over TLS | Real-time streaming via Fluentd output |
| HTTPS Webhook | POST with HMAC signature | Batched delivery with retry |
| Kafka | Kafka producer | For high-volume environments |
| File Export | JSONL + GPG encrypted | For air-gapped SIEM ingestion |

## 8.4 Metrics

### 8.4.1 Metric Categories

**Platform Health:**
- `sentinelcore_service_up` — Service availability gauge
- `sentinelcore_service_request_duration_seconds` — Request latency histogram
- `sentinelcore_service_request_total` — Request count by service, method, status
- `sentinelcore_service_error_total` — Error count by service and error type

**Scan Operations:**
- `sentinelcore_scans_total` — Scan count by type, status, trigger
- `sentinelcore_scan_duration_seconds` — Scan duration histogram
- `sentinelcore_scan_queue_depth` — Pending scans in queue
- `sentinelcore_scan_workers_active` — Currently active workers
- `sentinelcore_scan_findings_total` — Findings per scan by severity

**Vulnerability Intelligence:**
- `sentinelcore_vuln_feed_sync_total` — Feed sync operations
- `sentinelcore_vuln_feed_last_sync_timestamp` — Last successful sync time
- `sentinelcore_vuln_total` — Total vulnerabilities in database
- `sentinelcore_vuln_active_exploited_total` — Actively exploited count

**Security:**
- `sentinelcore_auth_login_total` — Login attempts by result
- `sentinelcore_auth_token_issued_total` — Tokens issued
- `sentinelcore_scope_violation_total` — DAST scope violation attempts (critical alert)
- `sentinelcore_policy_evaluation_total` — Policy evaluation by result
- `sentinelcore_audit_integrity_check_total` — Audit integrity verifications

### 8.4.2 Alerting Rules

| Alert | Severity | Condition |
|---|---|---|
| ScopeViolationDetected | CRITICAL | `sentinelcore_scope_violation_total` increases |
| AuditIntegrityFailure | CRITICAL | Integrity verification returns mismatch |
| ScanWorkerDown | HIGH | Worker heartbeat missing > 2 minutes |
| DatabaseConnectionPoolExhausted | HIGH | Available connections < 5 |
| ScanQueueBacklog | MEDIUM | Queue depth > 100 for > 10 minutes |
| VulnFeedSyncFailed | MEDIUM | Feed sync failed for > 24 hours |
| CertificateExpiryImminent | HIGH | Certificate expires in < 7 days |

## 8.5 Distributed Tracing

### 8.5.1 Trace Propagation

- W3C Trace Context headers propagated across all gRPC and HTTP calls
- NATS messages include trace context in message headers
- Scan jobs carry trace context from trigger through completion

### 8.5.2 Key Trace Spans

```
scan.lifecycle (root span)
├── scan.validation
│   ├── scope.check
│   └── policy.evaluation
├── scan.dispatch
│   └── nats.publish
├── scan.execution
│   ├── sast.analysis (or dast.analysis)
│   │   ├── source.clone (SAST) or discovery.crawl (DAST)
│   │   ├── rules.load
│   │   ├── analysis.run
│   │   └── results.publish
│   └── evidence.upload
├── scan.correlation
│   ├── correlation.match
│   └── findings.enrich
└── scan.completion
    └── notification.send
```

## 8.6 Dashboards

SentinelCore ships with pre-built Grafana dashboards:

1. **Platform Overview** — Service health, active scans, queue depths
2. **Scan Operations** — Scan throughput, duration, success rates
3. **Security Posture** — Finding trends, severity distribution, SLA metrics
4. **Vulnerability Intelligence** — Feed freshness, new CVEs, active exploitation
5. **Audit Activity** — Login activity, policy evaluations, configuration changes
6. **Infrastructure** — CPU, memory, disk, network per service
