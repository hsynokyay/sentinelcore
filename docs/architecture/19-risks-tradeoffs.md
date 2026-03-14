# 19. Major Risks and Design Tradeoffs

## 19.1 Architecture Risks

### 19.1.1 Risk Registry

| ID | Risk | Probability | Impact | Mitigation |
|---|---|---|---|---|
| R-01 | DAST worker escapes scan scope and hits unauthorized targets | Low | Critical | Multi-layer scope enforcement (application-level + Kubernetes NetworkPolicy + DNS validation); hourly scope enforcement testing; automatic scan abort on any scope violation |
| R-02 | Malicious code in scanned repository achieves RCE in SAST worker | Medium | High | Sandboxed execution (seccomp, AppArmor, no network, non-root); ephemeral pods destroyed after each scan; resource limits prevent crypto-mining |
| R-03 | Supply chain attack via tampered update bundle | Low | Critical | Ed25519 signature verification with pinned public key; separate signing keys for platform/rules; HSM-protected private keys |
| R-04 | Audit log tampering obscures security incident | Low | Critical | HMAC integrity chain; append-only database access; hourly integrity verification; separation of duties (audit service has no delete permissions) |
| R-05 | Credential leakage from Auth Session Broker | Low | Critical | Credentials fetched from Vault per-request; never cached beyond session; never logged; memory-safe handling with secure wipe |
| R-06 | PostgreSQL single point of failure | Medium | High | Patroni HA with synchronous replication; automated failover; continuous WAL archiving; daily backup verification |
| R-07 | Air-gapped vuln intelligence becomes stale | Medium | Medium | Freshness indicator in dashboard; configurable warning thresholds; recommended import schedules per risk tier |
| R-08 | Worker resource exhaustion from adversarial input | Medium | Medium | Strict resource limits (CPU, memory, disk, time); per-file size limits; maximum file count per scan; parser timeout enforcement |
| R-09 | NATS JetStream message loss causing missing scan results | Low | High | At-least-once delivery; persistent streams; R3 replication; idempotent consumers; dead-letter queue for failed processing |
| R-10 | Key management failure (Vault seal event in production) | Medium | High | Shamir 3-of-5 key distribution; documented unseal procedures; regular unseal drills; auto-unseal option for cloud deployments |
| R-11 | Kubernetes cluster compromise | Low | Critical | Minimal RBAC for service accounts; Pod Security Standards (restricted); network policies; no host mounts; no privileged containers; admission controllers |
| R-12 | Performance degradation under large-scale scanning | Medium | Medium | HPA for worker scaling; queue-based load leveling; database partitioning; connection pooling; configurable concurrency limits |

### 19.1.2 Risk Monitoring

Each risk has associated metrics and alerts:

| Risk | Monitoring Metric | Alert |
|---|---|---|
| R-01 | `sentinelcore_scope_violation_total` | Any increment → CRITICAL |
| R-02 | Worker pod restart count, OOM kill count | Anomalous restarts → HIGH |
| R-04 | `sentinelcore_audit_integrity_check_total{result="fail"}` | Any failure → CRITICAL |
| R-06 | PostgreSQL replication lag | > 10 seconds → HIGH |
| R-07 | Vuln feed age | > configured threshold → MEDIUM |
| R-10 | Vault seal status | Sealed → CRITICAL |

## 19.2 Design Tradeoffs

### 19.2.1 Consistency vs. Performance

**Decision:** Synchronous PostgreSQL replication for findings and audit data.

| Pro | Con |
|---|---|
| Zero data loss for security-critical data | Higher write latency (~2x vs async) |
| Simpler reasoning about data integrity | Lower write throughput ceiling |
| Required for compliance (audit completeness) | Replication lag can stall writes |

**Mitigation:** Asynchronous processing via NATS for scan dispatch and non-critical writes. Only the final finding persistence and audit log writes are synchronous.

### 19.2.2 Security vs. Operational Convenience

**Decision:** mTLS for all internal service communication, even within the Kubernetes cluster.

| Pro | Con |
|---|---|
| Defense-in-depth: compromised pod cannot MITM other services | Increased operational complexity |
| Zero trust architecture | Certificate management overhead |
| Compliance requirement for many frameworks | Slightly higher latency per request |

**Mitigation:** cert-manager automates certificate lifecycle. Application-level mTLS means no service mesh dependency.

### 19.2.3 Offline-First vs. Developer Experience

**Decision:** System designed for air-gapped operation as primary mode.

| Pro | Con |
|---|---|
| Works in any environment (military, government, regulated) | More complex update process |
| No external dependency at runtime | Vulnerability intelligence may be stale in air-gapped mode |
| Maximum data sovereignty | Bundle distribution logistics overhead |

**Mitigation:** Online mode provides convenience when available. Semi-connected mode balances security and freshness. CLI tooling minimizes offline workflow friction.

### 19.2.4 Microservices vs. Monolith

**Decision:** Microservices with per-service deployment.

| Pro | Con |
|---|---|
| Independent scaling of scan workers | Higher operational complexity |
| Fault isolation (worker crash doesn't affect control plane) | Distributed system failure modes |
| Security isolation (least privilege per service) | More moving parts to monitor |
| Independent deployment of components | Network-dependent inter-service communication |

**Mitigation:** Single Docker Compose option for evaluation. Helm chart abstracts Kubernetes complexity. Comprehensive monitoring and alerting.

### 19.2.5 Embedded Dependencies vs. External Services

**Decision:** Embed NATS, allow PostgreSQL and MinIO to be either embedded or customer-provided.

| Pro | Con |
|---|---|
| NATS embedded: no external MQ dependency | Larger deployment footprint |
| Customer-managed DB option: leverage existing infrastructure | Must support multiple deployment modes |
| Self-contained deployment for air-gapped | Cannot leverage managed cloud services |

**Mitigation:** Helm chart supports both embedded and external modes for PostgreSQL and MinIO. Customer provides connection strings for external mode.

### 19.2.6 OPA vs. Built-In Authorization

**Decision:** OPA with Rego policies (Phase 2; hardcoded RBAC in MVP).

| Pro | Con |
|---|---|
| Policy-as-code: auditable, versionable | Learning curve for Rego |
| Extensible: customers can write custom policies | Additional component to operate |
| Industry standard | Policy evaluation adds latency (~1-5ms per evaluation) |

**Mitigation:** Ship with comprehensive default policies. Policy evaluation results are cached (with TTL). Policy engine is optional — hardcoded RBAC works without it.

### 19.2.7 SARIF as Primary Output Format vs. Custom Format

**Decision:** SARIF (Static Analysis Results Interchange Format) as primary output, with internal enriched format for storage.

| Pro | Con |
|---|---|
| Industry standard: compatible with GitHub, Azure DevOps, etc. | SARIF lacks some fields needed for DAST (HTTP traces) |
| Developer familiarity | SARIF schema is verbose for storage |
| IDE integration support | Must maintain mapping between internal and SARIF formats |

**Mitigation:** Internal storage uses enriched format with SARIF export as a transformation. DAST evidence stored separately with references from SARIF findings.

## 19.3 Technology Choice Justifications

| Choice | Alternatives Considered | Rationale |
|---|---|---|
| **Go** for control plane | Java, Rust | Low memory footprint, fast startup, excellent concurrency model, single-binary deployment, strong Kubernetes ecosystem |
| **PostgreSQL** | MySQL, CockroachDB | Row-level security, JSONB support, partitioning, mature ecosystem, Patroni HA, WAL-based replication |
| **NATS JetStream** | RabbitMQ, Kafka | Embedded mode (no external dependency), lightweight, JetStream provides persistence, simple clustering |
| **MinIO** | Ceph, local filesystem | S3-compatible API, erasure coding, easy to deploy, Kubernetes-native, supports WORM |
| **OPA** | Casbin, custom engine | Industry standard, Rego is powerful and auditable, large community, well-documented |
| **Ed25519** for signing | RSA, ECDSA | Small key/signature size, fast verification, strong security properties, no known weak parameters |
| **Helm** for deployment | Kustomize, Operator | Templating for multi-environment configs, wide adoption, established patterns |

## 19.4 Known Limitations

| Limitation | Impact | Planned Resolution |
|---|---|---|
| No real-time collaboration (findings triage) | Multiple analysts may triage same finding simultaneously | Optimistic locking with conflict resolution (Phase 2) |
| No built-in IDE plugin | Developers must use API/CLI to view findings | IDE plugins planned for Phase 4 |
| No native ticket system integration | Manual ticket creation from findings | Jira/ServiceNow integration planned for Phase 4 |
| Single-region deployment only (MVP) | No geographic redundancy | Multi-site replication planned for Phase 3 |
| No Windows scan target support for DAST | Cannot scan Windows-specific web servers | Evaluate demand; DAST is protocol-level, mostly OS-agnostic |
| SAST limited to top 8 languages initially | Some customer codebases may not be fully covered | Language support expanded incrementally based on demand |
| No binary analysis | Cannot analyze compiled artifacts without source | Out of scope; focus on source-code and runtime testing |
