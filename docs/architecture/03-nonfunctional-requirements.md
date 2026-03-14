# 3. Non-Functional Requirements

## 3.1 Performance

| ID | Requirement | Target |
|---|---|---|
| NFR-P-001 | SAST scan throughput | ≥ 50,000 lines of code per minute per worker |
| NFR-P-002 | DAST scan initiation latency | < 5 seconds from trigger to first request |
| NFR-P-003 | API response time (control plane) | p95 < 200ms for read operations |
| NFR-P-004 | API response time (control plane) | p95 < 500ms for write operations |
| NFR-P-005 | Vulnerability feed ingestion | Full NVD sync < 30 minutes |
| NFR-P-006 | Correlation engine processing | < 60 seconds for 10,000 findings |
| NFR-P-007 | Report generation | < 120 seconds for 50,000 findings |
| NFR-P-008 | Concurrent scans | ≥ 50 parallel scans with 10 workers |

## 3.2 Scalability

| ID | Requirement | Target |
|---|---|---|
| NFR-S-001 | Horizontal worker scaling | 1 to 100 scan workers with linear throughput increase |
| NFR-S-002 | Data retention | ≥ 2 years of scan history at full fidelity |
| NFR-S-003 | Project capacity | ≥ 10,000 projects per deployment |
| NFR-S-004 | Concurrent users | ≥ 500 concurrent API consumers |
| NFR-S-005 | Finding capacity | ≥ 10 million findings per deployment |

## 3.3 Availability and Reliability

| ID | Requirement | Target |
|---|---|---|
| NFR-A-001 | Control plane availability | 99.9% (8.7 hours downtime/year) |
| NFR-A-002 | Scan worker recovery | Auto-restart within 30 seconds of failure |
| NFR-A-003 | Scan resilience | Automatic retry with checkpoint resume on worker failure |
| NFR-A-004 | Data durability | Zero data loss for completed scan results |
| NFR-A-005 | Database recovery | RPO < 1 hour, RTO < 4 hours |
| NFR-A-006 | Graceful degradation | System remains queryable when scan workers are unavailable |

## 3.4 Security

| ID | Requirement | Target |
|---|---|---|
| NFR-SEC-001 | Encryption at rest | AES-256-GCM for all stored data |
| NFR-SEC-002 | Encryption in transit | mTLS for all internal service communication |
| NFR-SEC-003 | Credential isolation | Credentials never stored outside sealed vault; never in logs |
| NFR-SEC-004 | Network isolation | Each DAST worker runs in an isolated network namespace |
| NFR-SEC-005 | Audit log integrity | HMAC-SHA256 chain on all audit log entries |
| NFR-SEC-006 | Secret zero bootstrap | Vault unsealing via Shamir's Secret Sharing (3-of-5 threshold) |
| NFR-SEC-007 | Update integrity | Ed25519 signature verification on all update bundles |
| NFR-SEC-008 | RBAC enforcement | All API endpoints enforce role-based access checks |

## 3.5 Operability

| ID | Requirement | Target |
|---|---|---|
| NFR-O-001 | Deployment method | Helm chart for Kubernetes; single-node Docker Compose for evaluation |
| NFR-O-002 | Upgrade strategy | Rolling upgrades with zero downtime for control plane |
| NFR-O-003 | Configuration management | Declarative YAML configuration with schema validation |
| NFR-O-004 | Health monitoring | /healthz, /readyz, /livez endpoints on all services |
| NFR-O-005 | Log format | Structured JSON logs with OpenTelemetry trace correlation |
| NFR-O-006 | Backup | Automated daily backups with configurable retention |
| NFR-O-007 | Restore | Point-in-time restore from any backup within retention window |

## 3.6 Compliance

| ID | Requirement | Target |
|---|---|---|
| NFR-C-001 | Data residency | All data stored within customer's infrastructure boundary |
| NFR-C-002 | Audit trail completeness | Every state-changing operation has a corresponding audit entry |
| NFR-C-003 | Evidence chain of custody | Immutable evidence with cryptographic integrity verification |
| NFR-C-004 | Report reproducibility | Any historical report can be regenerated from stored data |
| NFR-C-005 | Regulatory alignment | Architecture supports SOC 2 Type II, ISO 27001, PCI DSS, FedRAMP evidence collection |

## 3.7 Compatibility

| ID | Requirement | Target |
|---|---|---|
| NFR-CM-001 | Kubernetes versions | 1.27+ |
| NFR-CM-002 | Container runtime | containerd, CRI-O |
| NFR-CM-003 | CPU architectures | x86_64 (primary), ARM64 (secondary) |
| NFR-CM-004 | Operating systems | Linux (RHEL 8+, Ubuntu 22.04+, Amazon Linux 2023) |
| NFR-CM-005 | Database | PostgreSQL 15+ |
| NFR-CM-006 | Identity providers | OIDC, LDAP, SAML 2.0, Active Directory |
