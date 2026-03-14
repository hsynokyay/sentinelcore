# 16. Operations and Scaling

## 16.1 Day-2 Operations

### 16.1.1 Routine Operations

| Operation | Frequency | Method | Automated |
|---|---|---|---|
| Health check review | Continuous | Grafana dashboard | Yes (alerts) |
| Backup verification | Daily | Automated job + spot check | Yes |
| Audit log integrity check | Hourly | CronJob | Yes |
| Certificate rotation | Automatic (24h) | cert-manager | Yes |
| Database vacuuming | Daily | PostgreSQL autovacuum + weekly manual | Partial |
| Log rotation | Daily | Fluentd/Loki retention | Yes |
| Vulnerability feed sync | Continuous / on-import | Vuln Intel Service | Yes |
| Worker pool right-sizing | Weekly | Review HPA metrics | Manual review |
| Capacity review | Monthly | Resource utilization report | Manual |
| DR drill | Quarterly | Full restore test | Manual |

### 16.1.2 Operational CLI

```bash
# Platform health
sentinelcore-cli status                    # Overall platform health
sentinelcore-cli status services           # Per-service health
sentinelcore-cli status workers            # Worker pool status
sentinelcore-cli status database           # Database health, replication lag
sentinelcore-cli status vault              # Vault seal status

# Scan management
sentinelcore-cli scan list --status running
sentinelcore-cli scan cancel <scan-id>
sentinelcore-cli scan retry <scan-id>

# Worker management
sentinelcore-cli workers list
sentinelcore-cli workers drain <worker-id>   # Graceful worker shutdown
sentinelcore-cli workers scale sast --replicas 10

# Maintenance
sentinelcore-cli maintenance enable          # Pause scan scheduling, show maintenance banner
sentinelcore-cli maintenance disable
sentinelcore-cli db vacuum --full            # Manual vacuum (maintenance window)
sentinelcore-cli db stats                    # Table sizes, index usage

# Audit
sentinelcore-cli audit search --actor jdoe --from 2026-03-01 --to 2026-03-14
sentinelcore-cli audit verify-integrity --from 2026-03-01
sentinelcore-cli audit export --from 2026-03-01 --format jsonl --output audit-export.jsonl
```

## 16.2 Scaling Strategy

### 16.2.1 Horizontal Scaling

| Component | Scaling Trigger | Scale Unit | Limit |
|---|---|---|---|
| SAST Workers | NATS queue depth > 5 per worker | 1-4 pods per scale event | 100 pods |
| DAST Workers | NATS queue depth > 3 per worker | 1-2 pods per scale event | 50 pods |
| Control Plane | CPU > 70% or request latency p95 > 500ms | 1 pod | 10 pods |
| Correlation Engine | Finding queue depth > 1000 | 1 pod | 5 pods |
| Reporting Service | Report generation queue > 5 | 1 pod | 5 pods |

### 16.2.2 Vertical Scaling

| Component | When to Scale Vertically | Typical Adjustment |
|---|---|---|
| PostgreSQL | Query latency increasing, buffer cache hit ratio < 95% | Increase memory (shared_buffers) |
| MinIO | Object throughput bottleneck | Increase CPU/memory per node |
| SAST Worker | Large codebase analysis (> 1M LOC) | Increase memory limit to 16Gi |
| Redis | Session count exceeding memory | Increase memory limit |

### 16.2.3 Database Scaling

**Read Scaling:**
- PostgreSQL read replicas for read-heavy queries (reports, finding search)
- Connection pooling via PgBouncer (transaction mode)
- Cache layer (Redis) for frequently accessed data (project configs, policies)

**Write Scaling:**
- Partitioning strategy: findings and audit logs partitioned by time range
- Batch writes for scan results (buffered in NATS, written in batches)
- Async audit log writes via NATS (guaranteed delivery, eventually consistent reads)

**Storage Scaling:**
- PostgreSQL: expand PVC size (online resize with supported storage class)
- MinIO: add nodes to distributed cluster (online expansion)
- NATS: increase stream storage limits

## 16.3 Capacity Planning

### 16.3.1 Sizing Guidelines

| Deployment Size | Projects | Scans/Day | Findings | Workers | DB Size | MinIO Size |
|---|---|---|---|---|---|---|
| Small | < 50 | < 20 | < 100K | 2 SAST, 2 DAST | 50 GB | 100 GB |
| Medium | 50–500 | 20–100 | 100K–1M | 5 SAST, 5 DAST | 200 GB | 500 GB |
| Large | 500–5000 | 100–500 | 1M–10M | 20 SAST, 10 DAST | 1 TB | 2 TB |
| Enterprise | 5000+ | 500+ | 10M+ | 50+ SAST, 20+ DAST | 5 TB+ | 10 TB+ |

### 16.3.2 Growth Projections

```
Storage growth rate (approximate):
- Findings: ~1 KB per finding (including metadata)
- Evidence: ~50 KB per finding (SAST), ~200 KB per finding (DAST)
- Audit logs: ~500 bytes per event, ~1000 events per scan
- Reports: ~1 MB per report

Example: 100 scans/day × 500 findings/scan:
- Findings: 50,000 findings/day × 1 KB = 50 MB/day = 18 GB/year
- Evidence: 50,000 × 100 KB avg = 5 GB/day = 1.8 TB/year
- Audit: 100 × 1000 × 500 B = 50 MB/day = 18 GB/year
```

## 16.4 Performance Tuning

### 16.4.1 PostgreSQL Tuning

```ini
# Key parameters for SentinelCore workload
shared_buffers = '8GB'                    # 25% of available RAM
effective_cache_size = '24GB'             # 75% of available RAM
work_mem = '256MB'                        # Per-sort/hash operation
maintenance_work_mem = '2GB'              # For VACUUM, CREATE INDEX
max_connections = 200                     # Via PgBouncer
max_wal_size = '4GB'
min_wal_size = '1GB'
checkpoint_completion_target = 0.9
wal_level = 'replica'
max_wal_senders = 5
synchronous_commit = 'on'                 # For data durability
random_page_cost = 1.1                    # For SSD storage
effective_io_concurrency = 200            # For SSD storage
```

### 16.4.2 NATS Tuning

```yaml
jetstream:
  max_memory: 2Gi
  max_file: 50Gi
  store_dir: /data/jetstream
  max_outstanding_catchup: 64Mi
```

### 16.4.3 Worker Tuning

```yaml
# SAST Worker optimization
sast:
  analysis:
    max_file_size: 10Mi          # Skip files larger than this
    max_files_per_scan: 50000    # Limit for extremely large repos
    parser_timeout: 300s         # Per-file parser timeout
    taint_analysis_depth: 10     # Max call-chain depth for taint tracking
    parallel_analyzers: 4        # Concurrent analysis threads per worker

# DAST Worker optimization
dast:
  crawler:
    max_depth: 10                # Crawl depth limit
    max_pages: 5000              # Maximum pages per scan
    page_timeout: 30s            # Per-page load timeout
  scanner:
    max_rps: 50                  # Maximum requests per second
    concurrent_checks: 10        # Parallel vulnerability checks
    response_timeout: 15s        # Per-request timeout
```

## 16.5 Monitoring and Alerting

### 16.5.1 SLA Monitoring

| SLA | Metric | Target | Alert Threshold |
|---|---|---|---|
| API Availability | HTTP 200 rate on /healthz | 99.9% | < 99.5% over 5 min |
| API Latency | p95 response time | < 200ms | > 500ms over 5 min |
| Scan Completion | Scans completed / scans initiated | > 95% | < 90% over 1 hour |
| Scan Queue Wait | Time from trigger to dispatch | < 5 min | > 15 min |
| Finding Processing | Time from scan complete to correlated findings | < 5 min | > 15 min |

### 16.5.2 Capacity Alerts

| Resource | Warning | Critical |
|---|---|---|
| Database disk usage | > 70% | > 85% |
| MinIO disk usage | > 70% | > 85% |
| NATS JetStream storage | > 70% | > 85% |
| PostgreSQL connections | > 70% of max | > 85% of max |
| Worker memory usage | > 80% of limit | > 95% of limit |
| PVC usage (any volume) | > 75% | > 90% |

## 16.6 Upgrade Procedures

### 16.6.1 Rolling Upgrade (Zero Downtime)

For minor and patch versions:

```bash
# 1. Pre-flight check
sentinelcore-cli upgrade preflight --to-version 1.3.1

# 2. Apply upgrade
helm upgrade sentinelcore sentinelcore/sentinelcore \
  --version 1.3.1 \
  --values values-production.yaml \
  --wait --timeout 600s

# 3. Verify
sentinelcore-cli status services
sentinelcore-cli upgrade verify
```

### 16.6.2 Major Version Upgrade (Maintenance Window)

For major versions with schema migrations:

```bash
# 1. Enter maintenance mode
sentinelcore-cli maintenance enable --message "Upgrading to v2.0.0"

# 2. Wait for in-flight scans to complete (or cancel)
sentinelcore-cli scan wait-all --timeout 1800

# 3. Create backup
sentinelcore-cli backup create --type full --wait

# 4. Apply database migrations
sentinelcore-cli db migrate --to-version 2.0.0 --dry-run  # Preview
sentinelcore-cli db migrate --to-version 2.0.0             # Apply

# 5. Upgrade services
helm upgrade sentinelcore sentinelcore/sentinelcore \
  --version 2.0.0 \
  --values values-production.yaml \
  --wait --timeout 600s

# 6. Verify and exit maintenance
sentinelcore-cli upgrade verify
sentinelcore-cli maintenance disable
```
