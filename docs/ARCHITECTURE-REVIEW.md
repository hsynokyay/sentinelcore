# SentinelCore Architecture — Critical Review

**Reviewer Role:** Principal Security Architect (self-review)
**Date:** 2026-03-14
**Verdict:** Architecture is structurally sound but has ~70 gaps that create implementation ambiguity and operational risk. No fundamental design flaws, but several **Critical** and **High** severity items must be resolved before implementation begins.

---

## 1. Missing Critical Capabilities

### CRIT-01: No Rate Limiting or Abuse Prevention on the Control Plane API [Critical]

**Gap:** The API Gateway mentions rate limiting in annotations (`nginx.ingress.kubernetes.io/limit-rps: "100"`) but there is no application-level rate limiting, no per-user/per-team throttling, and no abuse detection. A compromised CI/CD token could flood the system with scan requests.

**Resolution:** Add an application-level rate limiter (token bucket per API key, per user, per team) in the Control Plane. Define defaults: 100 req/min per user, 20 scan creations/hour per team, 1000 req/min per API key. Implement circuit breaker on downstream services.

---

### CRIT-02: No Scan Target Ownership Verification [Critical]

**Gap:** `scan_targets` table has `verified_at` and `verified_by` columns but the architecture never specifies HOW target ownership is verified. Anyone who can create a project can add any domain as a DAST target. This is a critical safety gap — an insider could add `production-banking.internal` as a scan target and launch active DAST testing against it.

**Resolution:** Mandate a target verification workflow:
1. DNS TXT record verification (`_sentinelcore-verify.example.com TXT "sc-verify=<token>"`)
2. OR HTTP well-known path verification (`https://example.com/.well-known/sentinelcore-verify`)
3. OR manual approval by `platform_admin` with documented justification
4. Verification must be re-validated periodically (every 90 days)

---

### CRIT-03: No Secret Detection False Positive Suppression [High]

**Gap:** SAST engine detects hardcoded secrets (FR-SAST-007) but there is no mechanism to suppress false positives for known-safe patterns (test fixtures, example configs, documentation snippets). Without this, teams will be flooded with noise and ignore real findings.

**Resolution:** Add a secret suppression mechanism:
- Inline suppression comments (`// sentinelcore:ignore-secret`)
- Per-project allowlist patterns (regex for known test tokens)
- Confidence scoring based on entropy + context analysis
- All suppressions audit logged

---

### CRIT-04: No Webhook Signature Verification for Inbound CI/CD Events [High]

**Gap:** CI/CD Connector receives webhooks from external systems but the architecture never specifies how inbound webhook authenticity is verified. GitHub, GitLab, and Jenkins all have different webhook signature schemes (HMAC-SHA256, token headers, etc.). Without verification, an attacker could trigger arbitrary scans.

**Resolution:** Implement per-platform webhook signature verification:
- GitHub: `X-Hub-Signature-256` HMAC verification
- GitLab: `X-Gitlab-Token` header matching
- Jenkins: Shared secret HMAC
- Generic: configurable HMAC header name and algorithm
- Reject all unsigned webhooks by default

---

### CRIT-05: No Finding Deduplication Across Projects [Medium]

**Gap:** Finding deduplication is specified within a single project (fingerprint-based) but there is no cross-project dedup. If 50 teams use the same vulnerable library, each gets independent findings with no shared remediation tracking.

**Resolution:** Add an organization-level vulnerability view that groups identical SCA findings across projects by (ecosystem, package, version, CVE). This enables centralized remediation tracking without violating team isolation (read-only cross-project aggregation for `security_director` role).

---

### CRIT-06: No Notification/Alerting Subsystem [High]

**Gap:** The architecture mentions "webhook notifications" for critical findings (Section 7.9) but there is no notification service, no notification configuration model, no notification templates, and no delivery tracking. Teams have no way to know when a scan completes or when a critical finding appears without polling the API.

**Resolution:** Add a Notification Service with:
- Channels: webhook, email (SMTP), Slack-compatible webhook
- Events: scan.completed, finding.critical_new, sla.breach, feed.updated
- Per-team notification configuration
- Delivery tracking with retry
- Template customization
- Air-gapped: notification to internal endpoints only

---

## 2. Ambiguous Architecture Decisions

### AMB-01: Correlation Engine Matching Algorithm is a Black Box [Critical]

**Gap:** Section 5.10 shows a single example (CWE-89 matching) but provides no algorithm, no scoring formula, no threshold definitions, and no handling of edge cases. The composite risk formula `risk = f(CVSS, exploitability, asset_criticality, exposure)` is stated but never defined. This is the core differentiator of the platform and it's the least specified component.

**Resolution:** Define the correlation algorithm formally:
```
Correlation Match Score = weighted_sum(
  cwe_match:         0.40 × (1.0 if exact CWE match, 0.5 if same CWE parent category),
  parameter_match:   0.25 × (1.0 if exact name, 0.5 if fuzzy match, 0.0 if no match),
  endpoint_match:    0.20 × (cosine_similarity(sast_route, dast_url_path)),
  temporal_match:    0.15 × (1.0 if same scan cycle, 0.7 if < 7 days apart)
)

Correlation Confidence:
  score >= 0.80 → HIGH
  score >= 0.50 → MEDIUM
  score >= 0.30 → LOW
  score <  0.30 → NO CORRELATION

Composite Risk Score = CVSS_base × exploit_multiplier × asset_criticality_weight
  exploit_multiplier: 1.0 (no known exploit), 1.5 (exploit exists), 2.0 (actively exploited / CISA KEV)
  asset_criticality_weight: critical=1.5, high=1.2, medium=1.0, low=0.7
```

---

### AMB-02: SAST Worker Sandbox Technology Unspecified [High]

**Gap:** Section 7.6 says "seccomp, AppArmor" but never specifies whether the sandbox uses gVisor, Kata Containers, plain Linux namespaces, or just pod-level security context. The phrase "ephemeral pod (or within a sandboxed container context)" implies two options without choosing one.

**Resolution:** Specify clearly:
- **Production:** Each SAST scan runs as a Kubernetes Job with:
  - `securityContext.runAsNonRoot: true`, `runAsUser: 65534`
  - `securityContext.readOnlyRootFilesystem: true`
  - Custom seccomp profile (allow: read, write, open, close, stat, mmap, brk, futex, clone — deny all others)
  - AppArmor profile restricting file access to `/tmp/scan-workspace` only
  - No gVisor/Kata required (overhead too high for scan throughput targets)
- **High-security option:** gVisor (`runsc`) runtime class for customers requiring VM-level isolation
- Document the specific seccomp profile as a JSON artifact in the repository

---

### AMB-03: Policy Conflict Resolution Undefined [High]

**Gap:** Policies cascade from Organization → Team → Project but the architecture never specifies what happens when policies conflict. If org policy says "max severity: high" and team policy says "max severity: critical", which wins?

**Resolution:** Define explicit conflict resolution:
- **Most restrictive wins** for security policies (scan scope, gate criteria)
- **Most specific wins** for operational policies (scan profiles, schedules)
- Policy evaluation returns full decision chain showing which policy contributed to the decision
- Conflicting policies logged as warnings in the admin dashboard

---

### AMB-04: "Configurable" Without Defaults — 15+ Instances [Medium]

**Gap:** Multiple sections use "configurable" without specifying default values. Implementers will choose arbitrary defaults that may not be safe.

**Resolution:** All configurable parameters must have documented defaults in a `defaults.yaml` reference. Key missing defaults:

| Parameter | Proposed Default |
|---|---|
| DAST max requests/second | 10 rps |
| DAST max concurrent connections | 5 |
| DAST crawl depth | 10 |
| DAST max pages per scan | 5,000 |
| SAST max file size | 10 MB |
| SAST max files per scan | 50,000 |
| SAST parser timeout per file | 120 seconds |
| Scan global timeout | 3,600 seconds (1 hour) |
| NATS message max size | 8 MB |
| Redis session TTL | 900 seconds (15 min, matching JWT) |
| Redis eviction policy | `volatile-lru` |
| PgBouncer pool mode | `transaction` |
| Audit log retention minimum | 1 year |
| Finding SLA (critical) | 7 days |
| Finding SLA (high) | 30 days |
| Finding SLA (medium) | 90 days |
| Finding SLA (low) | 180 days |

---

## 3. Security Gaps

### SEC-01: DNS Rebinding Attack on DAST Scope Enforcement [Critical]

**Gap:** Scope enforcement resolves domain → IP and blocks private IPs, but DNS rebinding is not addressed. An attacker-controlled target could resolve to a public IP during scope validation, then rebind to `127.0.0.1` during actual scanning, bypassing all SSRF protections.

**Resolution:**
1. Pin DNS resolution at scan start — cache resolved IPs for the scan duration
2. Re-validate resolved IP on every request (not just at scan start)
3. Implement "DNS pinning" — if resolved IP changes during scan, block the request and alert
4. Block all RFC 1918, link-local, loopback, and cloud metadata IPs (`169.254.169.254`) regardless of when resolution occurs

---

### SEC-02: Ed25519 Key Compromise Recovery is Circular [Critical]

**Gap:** Section 12.2.2 states "public keys can be rotated via a signed key rotation bundle (signed by the old key, containing the new key)." If the old private key is compromised, the attacker can sign a rotation bundle pointing to their own key. This is a single point of failure in the entire update supply chain.

**Resolution:**
1. Implement a **key rotation hierarchy**: a long-term root key (stored in HSM, used only for key rotation) and short-term signing keys (used for bundle signing)
2. Root key signs the rotation of signing keys — compromise of signing key does not compromise root
3. Alternative: ship two independent public keys; rotation requires signatures from BOTH keys (threshold signature scheme)
4. Emergency revocation: customer can manually pin a new public key via CLI (`sentinelcore-cli update set-key --key <new-key> --confirm-emergency`)

---

### SEC-03: Audit Log HMAC Key Rotation Invalidates Verification [High]

**Gap:** HMAC key rotates quarterly but the architecture never explains how entries signed with old keys are verified. If the verification job uses only the current key, all entries signed with previous keys will fail integrity checks.

**Resolution:**
- Store `hmac_key_version` column in audit log entries
- Vault retains all historical HMAC keys indexed by version
- Verification job loads the correct key per entry based on key version
- Key version transitions create a "key rotation" audit entry signed by BOTH old and new keys

---

### SEC-04: No CSRF Protection Specified for REST API [High]

**Gap:** The REST API serves external clients (browsers, CLI) but no CSRF protection is mentioned. If the API is ever accessed via a browser-based admin UI (even a minimal one), CSRF attacks could trigger scans or modify configuration.

**Resolution:**
- API authentication via `Authorization: Bearer` header (not cookies) — inherently CSRF-resistant for API clients
- If any cookie-based session is ever used, require `SameSite=Strict` and a custom header (`X-SentinelCore-Request: 1`)
- Document this as a security invariant: API MUST NOT use cookie-based authentication without CSRF tokens

---

### SEC-05: Worker-to-Control-Plane Communication Channel Trust [High]

**Gap:** Workers are "semi-trusted" but communicate scan results via NATS. If a DAST worker is compromised (via a malicious response from a scan target), it could inject false findings into NATS. There is no message-level integrity verification — mTLS authenticates the worker but doesn't verify message content.

**Resolution:**
- Workers sign result messages with their short-lived mTLS certificate
- Correlation Engine verifies message signature before processing
- Result messages include `worker_id`, `scan_id`, and `timestamp` — Correlation Engine validates these against Orchestrator's dispatch records
- Any result from an unknown worker or for an undispatched scan is rejected and alerting triggered

---

### SEC-06: No Memory-Safe Credential Handling Guarantee [Medium]

**Gap:** Section 7.7.1 claims "memory-safe handling with secure wipe" but Go (the Auth Session Broker language) has a garbage collector that may copy credentials in memory before wiping. Python (used in analysis modules) has even weaker memory guarantees.

**Resolution:**
- Acknowledge the limitation: GC-managed languages cannot guarantee secure memory wipe
- Minimize credential exposure window: fetch from Vault → use immediately → zero the byte slice → discard reference
- Use Go's `memguard` or similar library for sensitive data handling in the Auth Session Broker
- Document that credentials may exist in GC-managed memory for the duration of a scan session (accepted risk with mitigations: ephemeral pods, short session TTLs)

---

## 4. Operational Gaps

### OPS-01: No Runbook for Vault Unseal Ceremony [Critical]

**Gap:** Shamir 3-of-5 unsealing mentioned repeatedly but no operational procedure exists: who holds keys, how they communicate, timeouts, fallback if holders are unavailable, authentication of key holders, or remote unseal protocol.

**Resolution:** Create a formal unseal runbook:
1. Key holders identified by role (not individual) with backup holders
2. Communication via pre-established secure channel (internal IM, phone tree)
3. Each holder authenticates via corporate SSO before providing their share
4. Timeout: 30 minutes from first share to completion; escalation to backup holders at 15 minutes
5. Unseal is audit logged (externally, since Vault is sealed)
6. Annual key holder rotation ceremony
7. Document as an operational runbook, not in architecture spec

---

### OPS-02: Orphaned NetworkPolicy Cleanup Missing [High]

**Gap:** Dynamic NetworkPolicies are created per DAST scan and "deleted automatically when scan completes." But if the Orchestrator crashes during cleanup, policies are orphaned. No garbage collection job exists.

**Resolution:**
- Add a `sentinelcore.io/expires` annotation on dynamic NetworkPolicies (already shown in Section 7.5.2 but never referenced by a cleanup mechanism)
- Implement a CronJob (`network-policy-gc`) running every 5 minutes that deletes expired NetworkPolicies
- On Orchestrator startup, reconcile: delete all NetworkPolicies for scans that are not in `running` state
- Alert if orphaned policies exist for > 10 minutes

---

### OPS-03: No First-Run / Bootstrap Procedure [High]

**Gap:** The architecture specifies ongoing operations but never describes initial setup: how is the first `platform_admin` user created? How is the database schema initialized? How is Vault initialized for the first time? How are the initial signing keys imported?

**Resolution:** Define a bootstrap sequence:
```
1. helm install sentinelcore ...
2. Init job runs: creates database schemas, seeds system policies
3. Vault init: generates Shamir shares, outputs to secure terminal
4. Bootstrap CLI: sentinelcore-cli bootstrap --admin-user <email>
   → Creates first platform_admin with temporary password
   → Imports default rule sets
   → Imports initial vulnerability intelligence (if bundle provided)
5. Admin logs in, changes password, configures IdP
```

---

### OPS-04: No Log Volume Estimation or Retention Sizing [Medium]

**Gap:** Log collection is specified (Fluentd → Loki) but there is no estimation of log volume and no Loki retention configuration. At 100 scans/day with DEBUG enabled, log volume could be 10+ GB/day.

**Resolution:**
- Default log level: INFO in production (DEBUG only via explicit override with auto-revert after 1 hour)
- Estimated log volume at INFO: ~500 MB/day for medium deployment
- Loki retention: 30 days default, configurable
- Alert when Loki storage exceeds 80% of allocated volume

---

### OPS-05: Patroni Split-Brain Scenario Unaddressed [High]

**Gap:** Patroni manages PostgreSQL HA with synchronous replication, but the architecture doesn't address network partition scenarios. If primary and replica are in separate failure domains and lose connectivity, Patroni's behavior depends on configuration not specified here.

**Resolution:**
- Specify Patroni DCS (Distributed Configuration Store): etcd or Kubernetes endpoints
- Require 3-node etcd cluster for quorum-based leader election (or Kubernetes lease-based leader election with 3+ control plane nodes)
- Specify `synchronous_mode_strict: true` — primary stops accepting writes if replica is unreachable (data safety over availability)
- Document the tradeoff: this means a single replica failure causes write downtime. Mitigation: add a second synchronous replica (3-node PostgreSQL minimum for critical deployments)

---

## 5. Compliance/Audit Gaps

### COMP-01: No Data Classification Scheme [High]

**Gap:** The architecture encrypts everything but never classifies data sensitivity levels. Without classification, all data receives the same protection level, making it impossible to implement proportional controls or prove to auditors that high-sensitivity data receives additional protection.

**Resolution:** Define data classification:

| Classification | Examples | Controls |
|---|---|---|
| CRITICAL | Vault secrets, signing keys, credentials | HSM/Vault only, never in database, audit on every access |
| HIGH | Findings with exploit evidence, scan credentials config | Encrypted at rest + column-level, team-scoped RLS |
| MEDIUM | Scan metadata, project configuration, user profiles | Encrypted at rest, standard RLS |
| LOW | Rule definitions, vulnerability intelligence (public data) | Encrypted at rest, minimal access control |

---

### COMP-02: No Evidence Tamper Detection at Read Time [High]

**Gap:** Evidence artifacts have SHA-256 hashes computed at creation, but the architecture never specifies that hashes are VERIFIED when evidence is read or exported. Without read-time verification, tampered evidence could be included in compliance reports without detection.

**Resolution:**
- Verify SHA-256 hash on every evidence read operation
- Hash verification failure: return error, alert, mark finding as "evidence_integrity_compromised"
- Compliance report generation MUST verify all included evidence
- Add `evidence_integrity_verified_at` timestamp to findings

---

### COMP-03: Audit Log Deletion for Retention is Not Audited [Medium]

**Gap:** Audit log partitions are dropped after retention period, but the deletion itself is not recorded anywhere. An auditor cannot verify that deletion followed policy.

**Resolution:**
- Before dropping a partition, write a "retention_enforcement" audit entry to the CURRENT partition containing: partition name, date range, record count, policy reference
- Export partition to encrypted archive BEFORE dropping
- Archive metadata (date range, record count, archive checksum) stored permanently in `audit.retention_log` table

---

### COMP-04: No Chain of Custody for Offline Bundle Transfers [Medium]

**Gap:** Section 14.5.1 shows a transfer checklist with "chain of custody form signed" but this is a manual process with no digital enforcement. The platform cannot verify WHO transferred the bundle or WHEN.

**Resolution:**
- Bundle manifest includes `transfer_id` field populated by the Transfer Station
- Transfer Station logs import with operator identity (badge scan / login)
- Update Manager records transfer metadata: operator, timestamp, media serial number
- Audit trail connects bundle → transfer → import → application

---

## 6. Scalability Risks

### SCALE-01: PostgreSQL Write Bottleneck Under Heavy Scan Load [High]

**Gap:** All findings write to a single PostgreSQL primary (even with partitioning). At Enterprise scale (500+ scans/day, 250K+ findings/day), synchronous replication to the standby doubles write latency. The architecture provides no write-scaling strategy beyond "batch writes via NATS."

**Resolution:**
- Specify batch insert strategy: Correlation Engine buffers findings and writes in batches of 500 (using `COPY` protocol, not individual `INSERT`)
- Add a write-ahead buffer: findings are first written to NATS JetStream (durable), then batch-inserted to PostgreSQL by a dedicated writer service. This decouples scan speed from database write speed
- For Enterprise scale: consider PostgreSQL partitioning by `project_id` with partition-level parallel writes
- If write throughput exceeds single-primary capacity: evaluate Citus extension for distributed PostgreSQL (documented as a scaling escape hatch, not default)

---

### SCALE-02: NATS Message Size Limit for Large Scan Results [High]

**Gap:** NATS has a default max message size of 1 MB. A scan with 50,000 findings serialized as JSON could exceed this. The architecture never specifies whether results are sent as a single message or batched.

**Resolution:**
- NATS max message size: set to 8 MB
- Scan results published as individual findings (one message per finding) with batch headers: `{scan_id, batch_number, total_batches, finding_count}`
- Large evidence artifacts: upload to MinIO first, publish MinIO reference in NATS message (never embed binary data in NATS)
- Correlation Engine processes findings as a stream, not as a single batch

---

### SCALE-03: MinIO Scaling Path Unclear [Medium]

**Gap:** MinIO distributed mode requires 4+ nodes and uses erasure coding. Adding nodes to an existing cluster requires careful planning (expansion must maintain parity groups). The architecture says "add nodes to distributed cluster (online expansion)" without noting the constraint that nodes must be added in sets of 4.

**Resolution:** Document MinIO scaling constraints:
- Initial deployment: 4 nodes minimum (EC:2, survives 2 failures)
- Expansion: add in sets of 4 nodes (server pools)
- Alternative for small deployments: single-node MinIO with backup to NFS (no erasure coding, rely on backup for durability)

---

## 7. Air-Gapped Deployment Gaps

### AIRGAP-01: No Bundle Size Estimation [High]

**Gap:** Bundles must be transferred via "approved media" but no size estimates are provided. If the full NVD + OSV + GitHub Advisory dump is 2 GB and the platform update with container images is 5 GB, the transfer media and time requirements are significant but unstated.

**Resolution:** Provide bundle size estimates:

| Bundle Type | Estimated Size (full) | Estimated Size (incremental) |
|---|---|---|
| Platform update | 3–5 GB (container images dominate) | 500 MB–2 GB |
| Rule update | 50–100 MB | 5–20 MB |
| Vulnerability intelligence (full) | 1–2 GB | 50–200 MB |
| Total initial deployment | 5–8 GB | N/A |

---

### AIRGAP-02: No Offline License Validation Mechanism [High]

**Gap:** Section 14.6.2 mentions "node-locked or hardware-fingerprinted" licenses but never specifies the fingerprinting mechanism, the license file format, or how license validation works without network access.

**Resolution:**
- License file: signed JSON containing customer ID, deployment ID, node fingerprint (SHA-256 of: CPU model + disk serial + MAC address), expiry date, feature flags
- Signed with vendor's licensing key (separate from update signing key)
- Validated at startup and daily by the Control Plane
- Fingerprint drift tolerance: 1 of 3 hardware attributes can change (for hardware replacement)
- Grace period: 30 days after expiry with persistent warning

---

### AIRGAP-03: Time Synchronization Failure Mode Undefined [Medium]

**Gap:** Section 14.4.2 states "SentinelCore validates time sync at startup and alerts on clock drift > 5 seconds" but doesn't specify what happens if drift exceeds the threshold. Do scans stop? Do certificates fail? Is it just a warning?

**Resolution:**
- Drift > 5 seconds: WARNING alert, log entry, dashboard banner
- Drift > 30 seconds: ERROR alert, TLS certificate validation may fail, new scan creation blocked with error message
- Drift > 60 seconds: CRITICAL alert, all services enter degraded mode (read-only, no new scans, no new tokens issued)
- Resolution: operator must fix NTP and restart affected services

---

## 8. RBAC / Governance Gaps

### RBAC-01: No Break-Glass / Emergency Access Procedure [Critical]

**Gap:** If all `platform_admin` accounts are locked (password expired, IdP down, Vault sealed), there is no emergency access procedure. The system becomes permanently inaccessible.

**Resolution:**
- Implement a break-glass account: local-only, disabled by default, requires physical access to the cluster
- Break-glass activation: `sentinelcore-cli emergency-access --shamir-shares <share1> <share2> <share3>`
- Uses 3-of-5 Shamir shares (same holders as Vault unseal or a separate set)
- All break-glass actions logged to a separate tamper-evident file log (not PostgreSQL, which may be inaccessible)
- Break-glass session auto-expires after 4 hours

---

### RBAC-02: Developer Role Can Trigger SAST Scans Without Scope Review [High]

**Gap:** Section 9.3.2 allows developers to trigger SAST scans for their projects. While SAST doesn't interact with external targets, a malicious developer could repeatedly trigger expensive SAST scans to consume worker resources (denial of service).

**Resolution:**
- Developer scan trigger: rate limit to 5 per hour per user
- Developer scans inherit the team's resource quota (already defined)
- Add `scan_priority` field: developer-triggered scans run at LOW priority, team-lead scans at NORMAL, scheduled scans at HIGH

---

### RBAC-03: No Delegation or Temporary Privilege Escalation [Medium]

**Gap:** If a `security_lead` is on vacation, there is no way to temporarily grant their permissions to an `analyst` without permanently changing their role. This creates operational friction.

**Resolution:**
- Implement time-bound role grants: `sentinelcore-cli rbac grant-temporary --user jdoe --role security_lead --team alpha --duration 7d --reason "covering for jsmith PTO"`
- Requires approval from `team_admin`
- Auto-expires, audit logged at grant, use, and expiry
- Maximum duration: 30 days

---

### RBAC-04: No Separation of Duties Enforcement for Policy Changes [High]

**Gap:** Section 9.7 shows approval workflows but `platform_admin` can unilaterally modify global policies. A compromised admin account could weaken scan scope policies without oversight.

**Resolution:**
- Global policy modifications require approval from a SECOND `platform_admin` or `security_director`
- Implement a pending-approval state for policy changes
- Changes to scan scope policies (domain allowlists) require approval from both `team_admin` AND `security_lead`
- Emergency policy changes (single approver) permitted but flagged in compliance reports

---

## 9. Data Model Gaps

### DATA-01: Missing `evidence_hash` Column in Findings Table [Critical]

**Gap:** Section 5.11 states "every artifact has a SHA-256 hash stored in the findings database" but the schema (Section 6.4) only has `evidence_ref TEXT` — there is no hash column. Evidence integrity verification is impossible as specified.

**Resolution:** Add to `findings.findings`:
```sql
evidence_hash   TEXT,               -- SHA-256 hash of evidence artifact
evidence_size   BIGINT,             -- evidence artifact size in bytes
```

---

### DATA-02: Finding Immutability Not Enforced at Database Level [High]

**Gap:** Section 6.4 states findings are "immutable records" but the schema allows `UPDATE` on the `status` column and other fields. Application logic is the only enforcement — a bug or direct database access could mutate findings.

**Resolution:**
- Add a database trigger that prevents UPDATE on core finding fields (title, description, severity, file_path, url, code_snippet, evidence_ref, evidence_hash)
- `status`, `last_seen_at`, `scan_count`, and `correlated_finding_ids` are mutable (updated by Correlation Engine)
- Alternative: make findings fully immutable and move `status` to a materialized view over `finding_state_transitions`

---

### DATA-03: No Index on `findings.dependency_name` for Non-SCA Findings [Medium]

**Gap:** Partial index `idx_findings_dependency` filters on `finding_type = 'sca'` but incremental rescan queries need to find ALL projects using a specific dependency — this requires scanning the SCA findings table across projects. Missing composite index for this query pattern.

**Resolution:** Add:
```sql
CREATE INDEX idx_findings_sca_pkg_project
  ON findings.findings(dependency_name, dependency_version, project_id)
  WHERE finding_type = 'sca';
```

---

### DATA-04: Missing `scan_jobs` to `scan_targets` Validation [Medium]

**Gap:** `scan_jobs.scan_target_id` references `scan_targets` but there is no constraint ensuring the scan target belongs to the same project as the scan job. A bug could associate a scan with the wrong target.

**Resolution:** Add a check constraint or application-level validation:
```sql
-- Application-level: verify scan_target.project_id = scan_job.project_id before dispatch
-- Or: composite foreign key (project_id, scan_target_id) referencing scan_targets(project_id, id)
```

---

### DATA-05: No Soft Delete Support in Schema [Medium]

**Gap:** Projects can be "archived" or "deleted" (status column) but findings, scans, and evidence reference projects by UUID. If a project is deleted, referential integrity constraints prevent deletion. The architecture mentions soft delete but never implements it consistently.

**Resolution:**
- All deletes are soft deletes (status = 'deleted')
- Add `deleted_at TIMESTAMPTZ` to projects, scan_targets, auth_configs
- Hard delete only via retention enforcement CronJob, which cascades to findings, evidence, and audit archives
- Hard delete requires `platform_admin` and is audit logged

---

## 10. What Must Be Clarified Before Implementation

### Priority 1 — Block implementation if unresolved

| # | Question | Blocking Component |
|---|---|---|
| 1 | **What is the exact correlation matching algorithm?** Weights, thresholds, scoring formula, edge case handling. | Correlation Engine |
| 2 | **What sandbox technology for SAST workers?** gVisor, Kata, or plain seccomp+AppArmor? Specific seccomp profile. | SAST Engine |
| 3 | **How is DAST target ownership verified?** DNS TXT, HTTP well-known, or admin approval? | DAST Engine, Control Plane |
| 4 | **How does Ed25519 key compromise recovery work?** Root key vs signing key hierarchy. | Update Manager |
| 5 | **How does break-glass emergency access work?** Shamir-based or separate mechanism? | Control Plane |
| 6 | **What is the bootstrap sequence?** First admin, first schema, first Vault init. | All components |

### Priority 2 — Resolve during first sprint

| # | Question | Blocking Component |
|---|---|---|
| 7 | How are DNS rebinding attacks prevented in DAST scope enforcement? | DAST Engine |
| 8 | What are the default values for all "configurable" parameters? | All components |
| 9 | How does audit HMAC key rotation preserve verification of old entries? | Audit Log Service |
| 10 | How are inbound CI/CD webhooks authenticated? | CI/CD Connector |
| 11 | What happens when Policy Engine is unavailable — fail open or fail closed? | Policy Engine |
| 12 | What is the NATS message batching strategy for scan results? | SAST/DAST Workers, Correlation Engine |
| 13 | How are orphaned NetworkPolicies cleaned up? | Orchestrator |
| 14 | How does Patroni behave during network partition? | PostgreSQL HA |

### Priority 3 — Resolve before Phase 2

| # | Question | Blocking Component |
|---|---|---|
| 15 | How does cross-project finding aggregation work without violating team isolation? | Findings Store |
| 16 | What notification channels and delivery guarantees are supported? | Notification Service (new) |
| 17 | How are temporary role grants implemented and expired? | RBAC |
| 18 | What is the data classification scheme and proportional controls? | All data stores |
| 19 | What are the offline bundle size estimates for transfer planning? | Update Manager |
| 20 | How does the system handle time synchronization failure in air-gapped mode? | All components |

---

## Summary Statistics

| Severity | Count |
|---|---|
| Critical | 12 |
| High | 28 |
| Medium | 19 |

**Conclusion:** The architecture provides a strong structural foundation with well-considered separation of concerns, security layering, and offline-first design. However, it suffers from underspecification in three critical areas: (1) the correlation algorithm, (2) DAST scope enforcement edge cases (DNS rebinding, redirect chains), and (3) key management recovery procedures. These must be resolved with concrete, implementable specifications before development begins. The remaining High and Medium items are typical for a first-pass architecture and can be resolved during implementation sprints, but they should be tracked as technical debt with defined resolution milestones.
