# 5. Service Architecture

## 5.1 Service Catalog

Each service is deployed as an independent Kubernetes Deployment with its own ServiceAccount, NetworkPolicy, and resource limits.

---

## 5.2 SentinelCore Control Plane

**Purpose:** Central API gateway and management layer for the entire platform.

| Property | Value |
|---|---|
| Binary | `sentinelcore-controlplane` |
| Language | Go |
| Port (gRPC) | 9000 |
| Port (REST) | 8080 |
| Port (metrics) | 9090 |
| Replicas | 2+ (HA) |
| Database Access | PostgreSQL (read/write) |
| Dependencies | Policy Engine, Audit Log Service, Redis |

**Responsibilities:**
- Serve external REST API (OpenAPI 3.1 spec)
- Serve internal gRPC API for inter-service communication
- Manage project, team, and user lifecycle
- Enforce authentication (OIDC/LDAP/SAML/local) via pluggable auth providers
- Delegate authorization checks to Policy Engine
- Publish state-change events to NATS
- Serve as the configuration authority for all platform settings

**API Domains:**
- `/api/v1/projects` — Project CRUD, team assignment
- `/api/v1/scans` — Scan lifecycle (create, cancel, status, results)
- `/api/v1/findings` — Finding query, triage, annotation
- `/api/v1/policies` — Policy CRUD, assignment
- `/api/v1/reports` — Report generation and retrieval
- `/api/v1/admin` — Platform administration, user management
- `/api/v1/system` — Health, configuration, license

---

## 5.3 SentinelCore Scan Orchestrator

**Purpose:** Manages the lifecycle of all scan operations from trigger to completion.

| Property | Value |
|---|---|
| Binary | `sentinelcore-orchestrator` |
| Language | Go |
| Port (gRPC) | 9001 |
| Replicas | 1 (leader-elected) + 1 standby |
| Database Access | PostgreSQL (read/write: scan_jobs table) |
| Dependencies | NATS, Control Plane, Policy Engine, Auth Session Broker |

**Responsibilities:**
- Accept scan requests from Control Plane or CI/CD Connector
- Validate scan scope against Policy Engine before dispatch
- Create dynamic Kubernetes NetworkPolicies for DAST scan targets
- Dispatch scan jobs to NATS worker queues
- Monitor worker heartbeats and scan progress
- Handle scan timeout, retry, and failure recovery
- Coordinate multi-phase scans (SAST → DAST → correlation)
- Manage scan scheduling (cron-based recurring scans)
- Clean up resources (NetworkPolicies, temp volumes) on scan completion

**Scan Job State Machine:**
```
PENDING → SCOPE_VALIDATING → DISPATCHED → RUNNING →
  COLLECTING → CORRELATING → COMPLETED
                                    │
  PENDING → ... → RUNNING → FAILED (retryable) → DISPATCHED (retry)
                           → FAILED (terminal)
                           → CANCELLED
                           → TIMED_OUT
```

**Worker Queue Strategy:**
- Separate NATS subjects per scan type: `scan.sast.dispatch`, `scan.dast.dispatch`
- Workers subscribe with queue groups for load distribution
- At-least-once delivery with idempotent processing (dedup by scan_job_id)

---

## 5.4 SentinelCore SAST Engine

**Purpose:** Performs static analysis on source code.

| Property | Value |
|---|---|
| Binary | `sentinelcore-sast-worker` |
| Language | Go + Python (analysis modules) |
| Port (metrics) | 9090 |
| Replicas | 1–N (HPA based on queue depth) |
| Database Access | None (stateless worker) |
| Dependencies | NATS, MinIO, Rule Repository |

**Responsibilities:**
- Subscribe to `scan.sast.dispatch` queue
- Clone/checkout source code from SCM to ephemeral volume
- Load applicable rules from Rule Repository
- Execute analysis pipeline:
  1. **Language Detection** — Identify languages in the codebase
  2. **Dependency Extraction** — Parse lock files and manifests for SCA
  3. **AST Parsing** — Build abstract syntax trees per language
  4. **Taint Analysis** — Trace data flow from sources (user input, external data) to sinks (SQL queries, command execution, file operations)
  5. **Pattern Matching** — Apply rule patterns against AST and code
  6. **Secret Detection** — Scan for hardcoded credentials using entropy analysis and pattern matching
  7. **SCA Matching** — Cross-reference dependencies against vulnerability intelligence
- Emit findings to `scan.results.sast` NATS subject
- Upload evidence artifacts to MinIO
- Report progress via heartbeat on `scan.progress` subject

**Isolation Model:**
- Each scan runs in an ephemeral pod (or within a sandboxed container context)
- Source code volume is tmpfs-backed and destroyed on completion
- No network egress permitted (all rules pre-loaded, no external calls)
- Resource limits enforced: CPU, memory, disk, wall-clock time

---

## 5.5 SentinelCore DAST Engine

**Purpose:** Performs dynamic security testing against running applications.

| Property | Value |
|---|---|
| Binary | `sentinelcore-dast-worker` |
| Language | Go |
| Port (metrics) | 9090 |
| Replicas | 1–N (HPA based on queue depth) |
| Database Access | None (stateless worker) |
| Dependencies | NATS, MinIO, Rule Repository, Auth Session Broker |

**Responsibilities:**
- Subscribe to `scan.dast.dispatch` queue
- Validate scan target against Orchestrator-provided scope document
- Obtain authenticated session from Auth Session Broker
- Execute scanning pipeline:
  1. **Scope Enforcement** — Verify every outbound request is within approved domain/IP/path scope
  2. **Discovery** — Crawl application within scope, parse OpenAPI specs, enumerate endpoints
  3. **Passive Analysis** — Analyze responses for information disclosure, security headers, cookie flags
  4. **Active Testing** — Send test payloads for injection, XSS, CSRF, authentication/authorization flaws
  5. **API Testing** — Test API endpoints against schema for input validation, auth bypass, rate limiting
  6. **Evidence Capture** — Record full HTTP request/response pairs for every finding
- Emit findings to `scan.results.dast` NATS subject
- Upload evidence (HTTP traces, screenshots) to MinIO
- Monitor session health; request re-authentication from Auth Session Broker if session expires

**Scope Enforcement (Critical Safety Feature):**
```
┌──────────────────────────────────────────────────┐
│              DAST Worker Scope Enforcer           │
│                                                   │
│  Every outbound HTTP request passes through:      │
│                                                   │
│  1. Domain allowlist check (exact + wildcard)     │
│  2. IP address resolution check (no SSRF)         │
│  3. Port allowlist check                          │
│  4. Path prefix check (if configured)             │
│  5. Protocol check (HTTP/HTTPS only)              │
│  6. Private IP range block (anti-SSRF)            │
│  7. Redirect chain validation (no scope escape)   │
│                                                   │
│  ANY check failure → request BLOCKED + logged     │
└──────────────────────────────────────────────────┘
```

**Rate Limiting:**
- Configurable requests-per-second per target
- Configurable concurrent connection limits
- Automatic backoff on HTTP 429 responses
- Scan profile presets: `passive` (read-only), `standard`, `aggressive`

---

## 5.6 SentinelCore Auth Session Broker

**Purpose:** Manages authentication credentials and sessions for DAST scanning.

| Property | Value |
|---|---|
| Binary | `sentinelcore-auth-broker` |
| Language | Go |
| Port (gRPC) | 9002 |
| Replicas | 2 (HA) |
| Database Access | PostgreSQL (read: auth_configs) |
| Dependencies | Vault, NATS |

**Responsibilities:**
- Store authentication configurations (login URLs, form fields, token endpoints)
- Retrieve credentials from Vault at scan time (never cache plaintext)
- Execute authentication sequences to obtain session tokens
- Provide session tokens to DAST workers via gRPC
- Monitor session validity; proactively re-authenticate before expiry
- Support authentication types:
  - Form-based login (username/password POST)
  - OAuth 2.0 Client Credentials and Authorization Code flows
  - API key / bearer token injection
  - Cookie-based sessions
  - Custom header injection
  - Multi-step login sequences (scripted)
- Audit log every credential access event

**Credential Flow:**
```
DAST Worker ──(gRPC)──► Auth Session Broker ──► Vault (fetch credential)
                                │
                                ▼
                        Target Application (login)
                                │
                                ▼
                        Session Token (returned to worker)
```

---

## 5.7 SentinelCore CI/CD Connector

**Purpose:** Integrates SentinelCore with CI/CD pipelines.

| Property | Value |
|---|---|
| Binary | `sentinelcore-cicd-connector` |
| Language | Go |
| Port (REST) | 8081 |
| Replicas | 2 (HA) |
| Database Access | PostgreSQL (read/write: pipeline_configs) |
| Dependencies | Control Plane, Scan Orchestrator, NATS |

**Responsibilities:**
- Receive webhook events from CI/CD systems
- Map pipeline events to scan triggers (push, PR, merge, tag)
- Provide pipeline-specific response formats (GitHub Check Runs, GitLab CI status)
- Apply gate policies: block merge if findings exceed thresholds
- Post scan summaries as PR/MR comments
- Supply CLI tool (`sentinelcore-cli`) for pipeline script integration

**Supported Platforms:**
- Jenkins (webhook + plugin)
- GitLab CI (webhook + .gitlab-ci.yml template)
- GitHub Actions (webhook + action)
- Azure DevOps (webhook + pipeline task)
- Generic webhook (any system supporting HTTP POST)
- CLI-triggered (for custom pipelines)

---

## 5.8 SentinelCore Vulnerability Intelligence Service

**Purpose:** Ingests, normalizes, and serves vulnerability data from public feeds.

| Property | Value |
|---|---|
| Binary | `sentinelcore-vuln-intel` |
| Language | Go |
| Port (gRPC) | 9003 |
| Replicas | 2 (HA) |
| Database Access | PostgreSQL (read/write: vuln_intelligence schema) |
| Dependencies | NATS, Update Manager (for offline bundles) |

**Responsibilities:**
- Ingest feeds: NVD (JSON feed API), CVE (via NVD), OSV (API/dump), GitHub Advisory Database (API/dump), CISA KEV (JSON feed)
- Normalize all feeds into unified internal schema
- Maintain CPE ↔ package mapping tables
- Calculate and store CVSS v3.1 base scores
- Integrate EPSS scores where available
- Track exploit availability and active exploitation status
- Publish new vulnerability events to NATS for incremental rescan triggering
- Support offline bundle ingestion (signed JSON bundles from Update Manager)
- Serve vulnerability lookup API for SAST/DAST enrichment

---

## 5.9 SentinelCore Rule Repository

**Purpose:** Stores, versions, and serves detection rules for SAST and DAST engines.

| Property | Value |
|---|---|
| Binary | `sentinelcore-rule-repo` |
| Language | Go |
| Port (gRPC) | 9004 |
| Replicas | 2 (HA) |
| Database Access | PostgreSQL (read/write: rules schema) |
| Dependencies | Update Manager, MinIO |

**Responsibilities:**
- Store SAST rules (pattern-based, taint-flow, AST-query)
- Store DAST rules (test payloads, detection patterns, scan sequences)
- Version all rules with semantic versioning
- Support rule categories: built-in, vendor-updated, customer-custom
- Protect customer custom rules from being overwritten by updates
- Serve rules to scan workers via gRPC with caching support
- Validate rule syntax on import
- Maintain rule metadata (CWE mapping, OWASP category, severity, confidence)

**Rule Layering:**
```
┌───────────────────────────┐
│  Customer Custom Rules    │  ← Highest priority (never overwritten)
├───────────────────────────┤
│  Vendor Update Rules      │  ← Updated via signed bundles
├───────────────────────────┤
│  Built-in Rules           │  ← Shipped with product version
└───────────────────────────┘
```

---

## 5.10 SentinelCore Correlation Engine

**Purpose:** Links findings across scan types and scan runs to produce deduplicated, enriched results.

| Property | Value |
|---|---|
| Binary | `sentinelcore-correlator` |
| Language | Go |
| Port (gRPC) | 9005 |
| Replicas | 2 (HA) |
| Database Access | PostgreSQL (read/write: findings schema) |
| Dependencies | NATS, Vuln Intelligence Service |

**Responsibilities:**
- Subscribe to `scan.results.sast` and `scan.results.dast` subjects
- Match SAST findings to DAST findings using:
  - CWE category correlation
  - URL path ↔ code route mapping
  - Parameter name matching
  - Vulnerability type alignment
- Deduplicate findings across scan runs (same vuln, new scan = update, not duplicate)
- Track finding first-seen / last-seen / scan-count
- Manage finding lifecycle state machine
- Enrich findings with vulnerability intelligence data (CVE, CVSS, EPSS, CISA KEV)
- Calculate composite risk score: `risk = f(CVSS, exploitability, asset_criticality, exposure)`
- Publish correlated findings to `findings.correlated` for downstream consumption

**Correlation Strategy:**
```
SAST Finding                    DAST Finding
  CWE-89 (SQL Injection)         CWE-89 (SQL Injection)
  File: UserController.java:42   URL: /api/users?id=1
  Param: id                      Param: id
           │                              │
           └──────────┬───────────────────┘
                      ▼
              Correlated Finding
              Confidence: HIGH (confirmed by both SAST + DAST)
              Evidence: code trace + HTTP request/response
```

---

## 5.11 SentinelCore Evidence Store

**Purpose:** Immutable storage for all scan evidence and artifacts.

| Property | Value |
|---|---|
| Binary | N/A (uses MinIO directly via shared library) |
| Storage Backend | MinIO (S3-compatible) |
| Dependencies | MinIO |

**Stored Artifacts:**
- SAST: code snippets, data flow graphs, dependency trees
- DAST: HTTP request/response pairs, screenshots, DOM snapshots
- SCA: dependency manifests, lock files
- Reports: generated PDF/HTML/JSON reports
- Audit exports: compliance report archives

**Storage Organization:**
```
evidence/
  {project_id}/
    {scan_id}/
      sast/
        {finding_id}/
          code_snippet.json
          data_flow.json
      dast/
        {finding_id}/
          http_trace.json
          screenshot.png
      metadata.json
      manifest.json (SHA-256 hashes of all artifacts)
```

**Integrity:**
- Every artifact has a SHA-256 hash stored in the findings database
- Manifest file per scan provides a Merkle-tree-like integrity chain
- MinIO versioning enabled — artifacts cannot be overwritten, only new versions created
- Object lock (WORM) available for compliance-critical deployments

---

## 5.12 SentinelCore Findings Store

**Purpose:** Persistent storage for all security findings with query and lifecycle management.

| Property | Value |
|---|---|
| Storage Backend | PostgreSQL (findings schema) |
| Access Pattern | Write via Correlation Engine; Read via Control Plane API |

**Design:**
- Findings are immutable records. State changes (triage, resolution) create new entries in the `finding_state_transitions` table.
- Full-text search index on finding descriptions and evidence summaries.
- Partitioned by project_id for query performance and data isolation.
- Row-level security policies enforce team-scoped access.

---

## 5.13 SentinelCore Policy Engine

**Purpose:** Centralized policy evaluation for access control, scan policies, and CI/CD gates.

| Property | Value |
|---|---|
| Binary | `sentinelcore-policy-engine` |
| Language | Go (OPA embedded) |
| Port (gRPC) | 9006 |
| Replicas | 2 (HA) |
| Database Access | PostgreSQL (read: policies schema) |
| Dependencies | OPA (embedded library) |

**Policy Domains:**
1. **Access Control Policies** — RBAC role-to-permission mappings, resource-level access rules
2. **Scan Policies** — Allowed scan targets, scan types, scan frequency, scope restrictions
3. **Gate Policies** — CI/CD gate criteria (max severity, CWE blocklist, minimum scan coverage)
4. **Data Policies** — Retention periods, data classification, evidence handling rules
5. **Network Policies** — DAST target allowlists, IP ranges, port restrictions

**Evaluation Flow:**
```
Requester ──(gRPC)──► Policy Engine
                         │
                         ├── Load applicable policies (cached)
                         ├── Build OPA input document
                         ├── Evaluate Rego policies
                         ├── Return allow/deny + reason
                         │
                         ▼
                   Audit Log (decision recorded)
```

---

## 5.14 SentinelCore Audit Log Service

**Purpose:** Append-only audit logging with tamper-evident integrity.

| Property | Value |
|---|---|
| Binary | `sentinelcore-audit` |
| Language | Go |
| Port (gRPC) | 9007 |
| Replicas | 2 (HA) |
| Database Access | PostgreSQL (append-only: audit_log schema) |
| Dependencies | NATS |

**Details:** See Section 8 (Logging, Audit and Observability) for full specification.

---

## 5.15 SentinelCore Reporting Service

**Purpose:** Generates compliance and technical reports from scan data.

| Property | Value |
|---|---|
| Binary | `sentinelcore-reports` |
| Language | Go + Python (report rendering) |
| Port (gRPC) | 9008 |
| Replicas | 2 |
| Database Access | PostgreSQL (read: findings, scans, projects) |
| Dependencies | MinIO, Findings Store |

**Report Types:**
- Executive Summary (high-level risk posture, trends)
- Technical Detail (full findings with evidence)
- Compliance Report (mapping to specific frameworks)
- Trend Analysis (vulnerability counts over time)
- Diff Report (changes between two scan runs)
- SLA Report (time-to-remediation metrics)

---

## 5.16 SentinelCore Update Manager

**Purpose:** Manages platform updates, rule updates, and vulnerability feed updates.

| Property | Value |
|---|---|
| Binary | `sentinelcore-updater` |
| Language | Go |
| Port (gRPC) | 9009 |
| Replicas | 1 |
| Database Access | PostgreSQL (read/write: updates schema) |
| Dependencies | MinIO, Rule Repository, Vuln Intelligence Service |

**Details:** See Section 12 (Update Distribution Architecture) for full specification.

---

## 5.17 SentinelCore AI Assist (Optional)

**Purpose:** Optional AI-powered finding analysis, remediation suggestion, and false positive detection.

| Property | Value |
|---|---|
| Binary | `sentinelcore-ai-assist` |
| Language | Python |
| Port (gRPC) | 9010 |
| Replicas | 0 (disabled by default) |
| Database Access | PostgreSQL (read: findings) |
| Dependencies | Control Plane, Local LLM runtime (e.g., vLLM, Ollama) |

**Design Principles:**
- **Completely optional** — System fully functional without it
- **No external API calls** — Uses only locally-hosted models
- **Human-in-the-loop** — AI suggestions require analyst confirmation
- **Audit logged** — All AI-generated suggestions are logged with provenance

**Capabilities (future):**
- Remediation code suggestion for common vulnerability patterns
- False positive confidence scoring
- Natural language finding summarization
- Cross-finding pattern detection

**Integration Pattern:**
```
Analyst requests AI analysis ──► Control Plane ──► AI Assist
                                                      │
                                                      ▼
                                               Local LLM Runtime
                                                      │
                                                      ▼
                                          Suggestion (with confidence)
                                                      │
                                                      ▼
                                      Analyst reviews and accepts/rejects
```
