# 15. Disaster Recovery Strategy

## 15.1 Recovery Objectives

| Metric | Target | Rationale |
|---|---|---|
| RPO (Recovery Point Objective) | < 1 hour | Maximum acceptable data loss window |
| RTO (Recovery Time Objective) | < 4 hours | Maximum acceptable downtime |
| MTTR (Mean Time to Recovery) | < 2 hours | Average expected recovery time |

## 15.2 Failure Scenarios and Recovery

### 15.2.1 Failure Classification

| Scenario | Severity | RPO | RTO | Recovery Method |
|---|---|---|---|---|
| Single worker pod crash | Low | 0 (no data loss) | < 30 seconds | Kubernetes auto-restart; scan retried from checkpoint |
| Control plane pod failure | Medium | 0 | < 60 seconds | Kubernetes auto-restart; HA replica takes over |
| Single data node failure | Medium | 0 (replicated) | < 5 minutes | PostgreSQL replica promotion; MinIO rebuilds from parity |
| Full cluster node failure | High | 0 (if replicated) | < 30 minutes | Kubernetes reschedules pods to surviving nodes |
| PostgreSQL primary failure | High | 0 (sync replication) | < 5 minutes | Patroni automatic failover to sync replica |
| Complete data loss | Critical | < 1 hour | < 4 hours | Restore from backup |
| Complete cluster destruction | Critical | < 1 hour | < 8 hours | Rebuild cluster + restore from off-site backup |
| Vault seal event | High | 0 | < 15 minutes | Unseal ceremony (3-of-5 key holders) |
| Ransomware / corruption | Critical | < 1 hour | < 4 hours | Restore from immutable backup (WORM) |

### 15.2.2 Component-Level Recovery

**PostgreSQL:**
- Synchronous replication to standby (RPO = 0 for committed transactions)
- Patroni manages automatic failover (< 30 second detection, < 30 second promotion)
- WAL archiving to MinIO for point-in-time recovery
- Daily full backup via pg_basebackup
- Continuous WAL streaming to backup location

**MinIO:**
- Erasure coding (EC:2) across 4+ nodes — survives 2 node failures
- Versioning enabled for all buckets — accidental deletion recoverable
- Cross-site replication to backup MinIO cluster (if available)
- Daily bucket-level backup via mc mirror

**NATS JetStream:**
- R3 replication across NATS cluster nodes
- Persistent streams survive pod restarts
- Cluster survives loss of 1 node (3-node cluster)

**Vault:**
- Raft storage with 3-node HA
- Automated snapshot every hour to encrypted backup
- Unsealing requires 3-of-5 Shamir key shares

## 15.3 Backup Strategy

### 15.3.1 Backup Schedule

| Component | Method | Frequency | Retention | Storage |
|---|---|---|---|---|
| PostgreSQL (full) | pg_basebackup | Daily at 02:00 | 30 days | MinIO backup bucket / external NFS |
| PostgreSQL (WAL) | Continuous archiving | Continuous | 7 days | MinIO backup bucket |
| MinIO (evidence) | mc mirror | Daily at 03:00 | 14 days | External NFS / tape |
| Vault (snapshot) | vault operator raft snapshot | Hourly | 7 days | Encrypted file on separate volume |
| Platform config | Helm values + ConfigMaps export | Daily at 01:00 | 90 days | Git repository (internal) |
| Kubernetes resources | Velero backup | Daily at 04:00 | 30 days | MinIO backup bucket / external NFS |

### 15.3.2 Backup Encryption

All backups are encrypted before writing to storage:

```
Backup data ──► Compress (zstd) ──► Encrypt (AES-256-GCM) ──► Write to storage
                                         │
                                    Key from Vault
                                    (backup-encryption-key)
```

### 15.3.3 Backup Verification

| Verification | Frequency | Method |
|---|---|---|
| Backup integrity | Daily | SHA-256 checksum verification |
| Backup restorability | Weekly | Automated restore test to isolated environment |
| Full DR drill | Quarterly | Complete restore to separate cluster |

### 15.3.4 Backup Commands

```bash
# Manual full backup
sentinelcore-cli backup create \
  --type full \
  --destination /backup/sentinelcore-backup-$(date +%Y%m%d).tar.gz.enc

# List available backups
sentinelcore-cli backup list

# Verify backup integrity
sentinelcore-cli backup verify \
  --backup /backup/sentinelcore-backup-20260314.tar.gz.enc

# Restore from backup
sentinelcore-cli backup restore \
  --backup /backup/sentinelcore-backup-20260314.tar.gz.enc \
  --confirm
```

## 15.4 Restore Procedures

### 15.4.1 Full Restore Procedure

```
1. Deploy fresh SentinelCore cluster (Helm install with --set restore.mode=true)
2. Initialize and unseal Vault (restore Vault snapshot or re-initialize)
3. Restore PostgreSQL from backup:
   a. Stop all application services
   b. Restore pg_basebackup
   c. Apply WAL logs to desired point-in-time
   d. Verify database integrity
4. Restore MinIO from backup:
   a. Restore bucket data via mc mirror
   b. Verify object integrity
5. Restore platform configuration:
   a. Apply Helm values
   b. Restore ConfigMaps and Secrets
6. Start application services
7. Run integrity verification:
   a. Audit log integrity check
   b. Evidence hash verification (sample)
   c. Service health checks
8. Restore complete — verify via smoke tests
```

### 15.4.2 Point-in-Time Recovery

PostgreSQL supports PITR using WAL archiving:

```bash
# Restore to specific timestamp
sentinelcore-cli backup restore \
  --type pitr \
  --target-time "2026-03-14T10:30:00Z" \
  --confirm
```

## 15.5 High Availability Design

### 15.5.1 HA Components

| Component | HA Strategy | Min Replicas | Failover Time |
|---|---|---|---|
| Control Plane | Active-Active behind Service | 2 | 0 (load balanced) |
| Orchestrator | Active-Passive (leader election) | 2 | < 15 seconds |
| PostgreSQL | Patroni (sync replication) | 2 | < 30 seconds |
| MinIO | Distributed mode (erasure coding) | 4 | 0 (automatic) |
| NATS | Clustered (Raft consensus) | 3 | < 5 seconds |
| Redis | Sentinel (master-replica) | 2 + sentinel | < 30 seconds |
| Vault | Raft HA | 3 | < 15 seconds |

### 15.5.2 Failure Detection

| Mechanism | Interval | Threshold |
|---|---|---|
| Kubernetes liveness probe | 10 seconds | 3 failures → restart |
| Kubernetes readiness probe | 5 seconds | 1 failure → remove from service |
| NATS heartbeat (workers) | 30 seconds | 2 missed → worker declared dead |
| Patroni health check | 10 seconds | 3 failures → failover |
| Vault health check | 10 seconds | Sealed → alert for unseal |
