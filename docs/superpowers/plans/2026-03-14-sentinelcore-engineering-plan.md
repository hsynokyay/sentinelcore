# SentinelCore Engineering Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Scope note:** This is the master engineering plan. Each development phase will produce a separate, detailed task-level implementation plan before work begins. This document defines WHAT is built and in what order — the per-phase plans define HOW.

**Goal:** Build SentinelCore from architecture specifications to a deployable, air-gap-capable application security platform with CI/CD-triggered SAST/DAST scanning, vulnerability intelligence, secure updates, and audit logging.

**Architecture:** 13 deployable services + 2 shared data libraries + 1 CLI tool, in Go (control plane, engines) and Python (analysis modules, reporting), communicating via gRPC (sync) and NATS JetStream (async), with PostgreSQL (findings, config, audit), MinIO (evidence), Redis (cache/sessions), and Vault (secrets). Deployed on Kubernetes with per-namespace network isolation and sandboxed scan workers.

**Tech Stack:** Go 1.22+, Python 3.12+, PostgreSQL 16, NATS 2.10+, MinIO, Redis 7+, HashiCorp Vault, Kubernetes 1.28+, Helm 3, OPA, cert-manager, OpenTelemetry, Prometheus, Grafana, Loki

---

## 1. System Implementation Overview

### Build Strategy

SentinelCore is built **bottom-up in concentric rings:**

```
Ring 0: Infrastructure   — Database, message queue, object storage, secrets
Ring 1: Core Platform    — Control Plane API, Auth, Policy, Audit
Ring 2: Scan Engines     — SAST Worker, DAST Worker, Auth Session Broker
Ring 3: Orchestration    — Scan Orchestrator, Scope Enforcement, NetworkPolicy
Ring 4: Intelligence     — Vuln Intel Service, Rule Repository, Correlation Engine
Ring 5: Integration      — CI/CD Connector, Reporting, Update Manager
```

Each ring depends only on rings below it. Within a ring, services can be built in parallel.

### Core Platform Foundations vs. Feature Modules

**Foundations (build once, used by everything):**

| Foundation | What it provides | Used by |
|---|---|---|
| `pkg/db` | PostgreSQL connection pool, migrations, RLS session setup | All services with DB access |
| `pkg/nats` | NATS JetStream client, consumer/producer helpers, message signing | All async communication |
| `pkg/auth` | JWT validation, session management, middleware | All API-facing services |
| `pkg/audit` | Audit event emission (wraps NATS publish to audit topic) | All services |
| `pkg/crypto` | Ed25519 verification, SHA-256 hashing, canonical JSON | Update Manager, Evidence Store |
| `pkg/config` | Layered config loading (defaults → Helm → ConfigMap → env) | All services |
| `pkg/observability` | OpenTelemetry setup (traces, metrics, structured logging) | All services |
| `pkg/grpc` | gRPC server/client scaffolding, mTLS interceptors, health checks | All inter-service calls |
| `pkg/testutil` | Test database setup, NATS test server, fixture helpers | All test suites |

**Feature modules** are the 15 services themselves — each is a separate Go module (or Python package for analysis/reporting) with its own `main.go`, Dockerfile, Helm template, and test suite.

### Repository Structure

```
sentinelcore/
├── cmd/                          # Service entry points
│   ├── controlplane/main.go
│   ├── orchestrator/main.go
│   ├── sast-worker/main.go
│   ├── dast-worker/main.go
│   ├── auth-broker/main.go
│   ├── cicd-connector/main.go
│   ├── vuln-intel/main.go
│   ├── rule-repo/main.go
│   ├── correlator/main.go
│   ├── policy-engine/main.go
│   ├── audit-service/main.go
│   ├── reporter/main.go
│   ├── updater/main.go
│   └── cli/main.go              # sentinelcore-cli
├── pkg/                          # Shared libraries (foundations)
│   ├── db/
│   ├── nats/
│   ├── auth/
│   ├── audit/
│   ├── crypto/
│   ├── config/
│   ├── observability/
│   ├── grpc/
│   └── testutil/
├── internal/                     # Service-specific logic
│   ├── controlplane/
│   ├── orchestrator/
│   ├── sast/
│   ├── dast/
│   ├── authbroker/
│   ├── cicd/
│   ├── vuln/
│   ├── rules/
│   ├── correlator/
│   ├── policy/
│   ├── audit/
│   ├── reporter/
│   └── updater/
├── api/                          # API definitions
│   ├── proto/                    # gRPC .proto files
│   └── openapi/                  # OpenAPI 3.1 specs
├── migrations/                   # PostgreSQL migrations (golang-migrate)
├── deploy/
│   ├── helm/sentinelcore/        # Helm chart
│   ├── docker-compose/           # Evaluation deployment
│   └── sandbox/                  # Seccomp/AppArmor profiles
├── rules/                        # Built-in SAST/DAST rule packs
├── policies/                     # Default OPA/Rego policies
├── scripts/                      # Build, test, ceremony scripts
├── docs/                         # Architecture docs (existing)
├── go.mod
├── go.sum
└── Makefile
```

---

## 2. Service Implementation Order

### Dependency Graph

```
                    ┌─────────────┐
                    │ PostgreSQL  │
                    │ NATS        │
                    │ MinIO       │
                    │ Redis       │
                    │ Vault       │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌───▼───┐ ┌─────▼─────┐
        │ Audit Log  │ │Policy │ │ Evidence  │
        │ Service    │ │Engine │ │ Store     │
        └─────┬──────┘ └───┬───┘ └─────┬─────┘
              │            │            │
        ┌─────▼────────────▼────────────▼─────┐
        │          Control Plane               │
        └──┬──────┬───────┬───────┬───────┬───┘
           │      │       │       │       │
     ┌─────▼──┐ ┌─▼────┐ │  ┌────▼───┐   │
     │Rule    │ │Auth  │ │  │Update  │   │
     │Repo   │ │Broker│ │  │Manager │   │
     └───┬───┘ └──┬───┘ │  └────────┘   │
         │        │      │               │
    ┌────▼────────▼──────▼────┐    ┌─────▼──────┐
    │   Scan Orchestrator     │    │ Vuln Intel  │
    └────┬──────────────┬─────┘    │ Service     │
         │              │          └──────┬──────┘
    ┌────▼────┐   ┌─────▼────┐           │
    │ SAST    │   │ DAST     │           │
    │ Worker  │   │ Worker   │           │
    └────┬────┘   └─────┬────┘           │
         │              │                │
         └──────┬───────┘                │
          ┌─────▼────────────────────────▼──┐
          │     Correlation Engine           │
          └─────────────┬───────────────────┘
                        │
              ┌─────────▼─────────┐
              │  CI/CD Connector  │
              │  Reporting        │
              └───────────────────┘
```

### Build Order

| Order | Service | Why this position | Parallel with |
|---|---|---|---|
| **0** | Infrastructure (PG, NATS, MinIO, Redis, Vault) | Everything depends on it | — |
| **0** | `pkg/*` shared libraries | Every service imports these | Infrastructure |
| **1** | Audit Log Service | Every service emits audit events; must exist first | Policy Engine |
| **1** | Policy Engine | Control Plane delegates all authz here | Audit Log Service |
| **1** | Evidence Store (MinIO client library) | Workers upload evidence here | Audit, Policy |
| **2** | Control Plane | Central API; all services register against it | — |
| **3** | Rule Repository | Workers need rules before scanning | Auth Session Broker |
| **3** | Auth Session Broker | DAST needs authenticated sessions | Rule Repository |
| **3** | Update Manager | Needed to import initial rules + vuln intel | Rule Repository |
| **4** | Scan Orchestrator | Coordinates workers; depends on Control Plane, Policy | — |
| **5** | SAST Worker | First scan engine | DAST Worker |
| **5** | DAST Worker | Second scan engine | SAST Worker |
| **6** | Vuln Intel Service | Enriches findings; can be built after basic scanning works | — |
| **7** | Correlation Engine | Needs findings from both SAST and DAST to correlate | — |
| **8** | CI/CD Connector | Integration layer; needs working scan pipeline | Reporting Service |
| **8** | Reporting Service | Needs findings and evidence | CI/CD Connector |

---

## 3. MVP Definition

**MVP Timeline:** 16 weeks (per architecture spec Section 17)
**MVP Goal:** A customer can trigger SAST and DAST scans via CI/CD webhook or API, view findings, and export results — with full audit logging, RBAC, scope enforcement, and signed update verification.

### MVP Functional Scope

| Capability | MVP Scope | Not in MVP |
|---|---|---|
| **Authentication** | Local accounts (bcrypt), JWT sessions | OIDC, LDAP, SAML, MFA |
| **Authorization** | Hardcoded RBAC (9 roles, permission matrix) | OPA/Rego, approval workflows |
| **SAST** | Java, Python, JavaScript; AST + taint analysis; SCA; secret detection | C#, Go, Ruby, PHP, C/C++; custom rules DSL |
| **DAST** | Web crawling, form-based auth, passive + active testing, scope enforcement | OAuth2 auth flows, API-schema-driven testing, checkpoint resume |
| **Scan Orchestration** | Manual + API + webhook trigger; single-phase scans | Scheduled scans, multi-phase orchestration, incremental SAST |
| **Vulnerability Intel** | NVD + CISA KEV (online + offline) | OSV, GitHub Advisory, EPSS; anomaly detection |
| **Correlation** | CWE-based SAST↔DAST matching; within-project dedup | Cross-project dedup, fuzzy matching |
| **Evidence** | MinIO storage, SHA-256 hashing, write-time integrity | Read-time verification, WORM mode |
| **Findings** | CRUD, severity filter, status transitions, fingerprint dedup | Full-text search, advanced queries |
| **CI/CD** | Webhook trigger (GitHub, GitLab), basic pass/fail gate | PR commenting, Azure DevOps, Jenkins plugin |
| **Reporting** | JSON/CSV export | PDF, scheduled reports, compliance mapping, trend analysis |
| **Updates** | Offline signed bundle import with full trust chain verification | Online pull, auto-update, rule-only hot-reload |
| **Audit** | Structured PostgreSQL events, all ops logged | HMAC integrity chain, SIEM export |
| **Deployment** | Docker Compose (eval) + Helm chart (K8s) | Air-gap bundle builder, HA configuration |
| **CLI** | `sentinelcore-cli` for bootstrap, scan trigger, trust management | Full operational CLI (maintenance, workers, etc.) |
| **Observability** | Structured JSON logs, Prometheus metrics, health endpoints | Distributed tracing, Grafana dashboards, Loki, Tempo |

### MVP Security Non-Negotiables

These are NOT deferrable. They ship in MVP or the product does not ship:

1. **DAST scope enforcement** — domain allowlist + private IP blocking + redirect validation + DNS pinning
2. **DAST target ownership verification** — DNS TXT, HTTP well-known, or platform_admin approval before any DAST scan
3. **SAST worker sandboxing** — no-network + ephemeral + non-root + read-only root (Phase 2); seccomp + AppArmor profiles applied and tested by end of MVP (Phase 4)
4. **Ed25519 bundle signature verification** — full trust chain (root → signing cert → manifest)
5. **Credential isolation** — Vault-fetched, never cached, audit-logged access
6. **Audit logging** — every state-changing operation produces an audit event
7. **RBAC enforcement** — role checks on every API endpoint
8. **Application-level rate limiting** — token bucket per user, per team, per API key
9. **Input validation** — all external inputs validated before processing
10. **TLS on external endpoints** — no plaintext API access
11. **Row-level security** — team-scoped data isolation at database level

### MVP Exit Criteria

- [ ] SAST scan completes on a Java/Python/JS project, produces findings with evidence
- [ ] DAST scan completes on a running web app, produces findings with HTTP traces
- [ ] DAST scope enforcer blocks requests to unapproved domains and private IPs
- [ ] DAST scan is blocked for unverified scan targets; verification via DNS TXT or admin approval works
- [ ] API rate limiter rejects excessive requests from a single user/API key
- [ ] CI/CD webhook triggers scan, gate policy returns pass/fail
- [ ] Vulnerability intelligence imported from NVD offline bundle, correlated with SCA findings
- [ ] Update bundle with tampered signature is rejected
- [ ] Non-admin user cannot access another team's findings (RLS enforced)
- [ ] All operations appear in audit log
- [ ] System deploys via `docker-compose up` and via `helm install`
- [ ] `sentinelcore-cli bootstrap` creates first admin and establishes trust

---

## 4. Engineering Work Breakdown

### 4.1 Control Plane

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-controlplane` |
| Ports | 8080 (REST), 9000 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL read/write (core, scans, findings schemas) |
| Dependencies | Policy Engine, Audit Log Service, Redis, NATS |

**Responsibilities:**
- External REST API (OpenAPI 3.1)
- Internal gRPC API for inter-service communication
- Project/team/user/scan-target CRUD
- **DAST target ownership verification** (DNS TXT, HTTP well-known, or admin approval — CRIT-02)
- Application-level rate limiting (token bucket per user, per team, per API key — CRIT-01)
- Authentication (local accounts MVP; OIDC/LDAP/SAML Phase 2)
- Authorization delegation to Policy Engine
- Scan lifecycle API (create, cancel, status, results)
- Finding query, triage, annotation API
- Configuration authority for platform settings
- Publish state-change events to NATS

**Major Components:**
- `internal/controlplane/server.go` — HTTP/gRPC server setup, middleware chain
- `internal/controlplane/api/` — REST handlers organized by domain (projects, scans, findings, admin)
- `internal/controlplane/auth/` — Local auth provider, JWT issuer, session manager
- `internal/controlplane/service/` — Business logic layer (project service, scan service, finding service)

**Key APIs:**
```
REST:
  POST   /api/v1/auth/login
  POST   /api/v1/auth/refresh
  GET    /api/v1/projects
  POST   /api/v1/projects
  POST   /api/v1/projects/{id}/scans
  GET    /api/v1/scans/{id}
  GET    /api/v1/findings?project_id=&severity=&status=
  PATCH  /api/v1/findings/{id}/status
  POST   /api/v1/projects/{id}/scan-targets/{tid}/verify   # Initiate DNS/HTTP verification
  GET    /api/v1/projects/{id}/scan-targets/{tid}/verify   # Check verification status
  POST   /api/v1/admin/scan-targets/{tid}/approve          # Manual admin approval
  GET    /api/v1/admin/users
  GET    /api/v1/system/health

gRPC (internal):
  ProjectService.GetProject
  ScanService.CreateScan, GetScanStatus
  FindingService.WriteFinding, QueryFindings
  ConfigService.GetConfig
```

---

### 4.2 Scan Orchestrator

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-orchestrator` |
| Ports | 9001 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL read/write (scans schema) |
| Dependencies | NATS, Control Plane, Policy Engine, Auth Session Broker |

**Responsibilities:**
- Accept scan requests (from Control Plane or CI/CD Connector)
- Validate scan scope against Policy Engine
- Create dynamic Kubernetes NetworkPolicies for DAST scans
- Dispatch scan jobs to NATS worker queues
- Monitor worker heartbeats and progress
- Handle scan timeout, retry, failure recovery
- Clean up resources (NetworkPolicies, temp volumes) on completion

**Major Components:**
- `internal/orchestrator/dispatcher.go` — Job dispatch to NATS with scope document
- `internal/orchestrator/lifecycle.go` — Scan state machine (pending → running → completed)
- `internal/orchestrator/netpol.go` — Kubernetes NetworkPolicy create/delete
- `internal/orchestrator/heartbeat.go` — Worker heartbeat monitoring, timeout enforcement
- `internal/orchestrator/gc.go` — Orphaned resource cleanup (startup reconciliation + periodic)

**Key APIs:**
```
gRPC:
  OrchestratorService.DispatchScan(ScanRequest) → ScanJob
  OrchestratorService.CancelScan(ScanID) → Result
  OrchestratorService.GetScanProgress(ScanID) → Progress

NATS Subjects:
  scan.sast.dispatch    — Publish scan jobs for SAST workers
  scan.dast.dispatch    — Publish scan jobs for DAST workers
  scan.progress         — Subscribe to worker heartbeats
  scan.results.sast     — Subscribe to SAST results
  scan.results.dast     — Subscribe to DAST results
```

---

### 4.3 SAST Engine

| Property | Value |
|---|---|
| Language | Go + Python (analysis modules) |
| Binary | `sentinelcore-sast-worker` |
| Ports | 9090 (metrics only) |
| DB access | None (stateless worker) |
| Dependencies | NATS, MinIO, Rule Repository |

**Responsibilities:**
- Subscribe to `scan.sast.dispatch` queue
- Clone source code from SCM to ephemeral tmpfs
- Load rules from Rule Repository
- Execute analysis: language detection → dependency extraction → AST parsing → taint analysis → pattern matching → secret detection → SCA
- Emit findings as individual NATS messages to `scan.results.sast`
- Upload evidence artifacts (code snippets, data flow graphs) to MinIO
- Report progress via heartbeat

**Major Components:**
- `internal/sast/worker.go` — NATS consumer, lifecycle management
- `internal/sast/pipeline.go` — Analysis pipeline orchestration
- `internal/sast/scm.go` — Git clone with depth=1, branch checkout
- `internal/sast/analyzers/` — Per-language analyzers (java, python, javascript)
- `internal/sast/taint/` — Taint analysis engine (source → sink tracking)
- `internal/sast/sca/` — Dependency extraction + vuln matching
- `internal/sast/secrets/` — Entropy + pattern-based secret detection
- `internal/sast/evidence.go` — Evidence packaging and MinIO upload

**Key APIs:**
```
NATS (consumer):
  scan.sast.dispatch — Receive scan jobs

NATS (producer):
  scan.results.sast  — Emit findings (one message per finding)
  scan.progress       — Emit heartbeats ({scan_id, phase, percent})

gRPC (client):
  RuleRepository.GetRules(engine_type=sast, language=java)
```

---

### 4.4 DAST Engine

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-dast-worker` |
| Ports | 9090 (metrics only) |
| DB access | None (stateless worker) |
| Dependencies | NATS, MinIO, Rule Repository, Auth Session Broker |

**Responsibilities:**
- Subscribe to `scan.dast.dispatch` queue
- Validate scan target against Orchestrator-provided scope document
- Obtain authenticated session from Auth Session Broker
- Execute scanning: scope enforcement → discovery/crawl → passive analysis → active testing → evidence capture
- Every outbound HTTP request passes through Scope Enforcer
- Emit findings to `scan.results.dast`
- Upload evidence (HTTP traces, screenshots) to MinIO

**Major Components:**
- `internal/dast/worker.go` — NATS consumer, lifecycle management
- `internal/dast/scope.go` — **Scope Enforcer** (domain allowlist, IP denylist, port check, redirect validation, DNS pinning)
- `internal/dast/crawler.go` — Web crawler with depth/page limits
- `internal/dast/passive.go` — Passive analysis (headers, cookies, info disclosure)
- `internal/dast/active.go` — Active testing (injection, XSS, CSRF payloads)
- `internal/dast/http.go` — HTTP client with scope enforcer transport, rate limiting
- `internal/dast/evidence.go` — HTTP trace capture, MinIO upload

**Key APIs:**
```
NATS (consumer):
  scan.dast.dispatch — Receive scan jobs (includes scope document)

NATS (producer):
  scan.results.dast  — Emit findings
  scan.progress       — Emit heartbeats

gRPC (client):
  AuthBroker.GetSession(auth_config_id) → SessionToken
  RuleRepository.GetRules(engine_type=dast)
```

---

### 4.5 Auth Session Broker

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-auth-broker` |
| Ports | 9002 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL read (auth.auth_configs) |
| Dependencies | Vault, NATS |

**Responsibilities:**
- Store auth configurations (login URLs, form fields, token endpoints)
- Retrieve credentials from Vault at scan time (never cache)
- Execute authentication sequences (form login, bearer token, API key)
- Provide session tokens to DAST workers via gRPC
- Audit log every credential access

**Major Components:**
- `internal/authbroker/service.go` — gRPC server, session lifecycle
- `internal/authbroker/providers/` — Auth type implementations (form, bearer, apikey, oauth2)
- `internal/authbroker/vault.go` — Vault KV client for credential retrieval

**Key APIs:**
```
gRPC:
  AuthBroker.GetSession(auth_config_id, scan_id) → SessionToken
  AuthBroker.RefreshSession(session_id) → SessionToken
  AuthBroker.RevokeSession(session_id) → Result
```

---

### 4.6 CI/CD Connector

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-cicd-connector` |
| Ports | 8081 (REST), 9090 (metrics) |
| DB access | PostgreSQL read/write (cicd schema) |
| Dependencies | Control Plane, Scan Orchestrator, NATS |

**Responsibilities:**
- Receive webhook events from CI/CD systems (GitHub, GitLab)
- Verify webhook signatures (HMAC)
- Map pipeline events to scan triggers
- Apply gate policies (block merge if findings exceed thresholds)
- Return scan results in platform-specific format

**Major Components:**
- `internal/cicd/webhook.go` — Webhook receiver, signature verification
- `internal/cicd/platforms/` — Platform-specific handlers (github, gitlab, generic)
- `internal/cicd/gate.go` — Gate policy evaluation (severity thresholds, CWE blocklists)

**Key APIs:**
```
REST:
  POST /webhook/github     — GitHub webhook receiver
  POST /webhook/gitlab     — GitLab webhook receiver
  POST /webhook/generic    — Generic HMAC-signed webhook

gRPC (client):
  Orchestrator.DispatchScan
  ControlPlane.GetScanResults
```

---

### 4.7 Vulnerability Intelligence Service

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-vuln-intel` |
| Ports | 9003 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL read/write (vuln_intel schema) |
| Dependencies | NATS, Update Manager (for offline bundles) |

**Responsibilities:**
- Ingest feeds: NVD, CISA KEV (MVP); OSV, GitHub Advisory, EPSS (Phase 2)
- Normalize all feeds into unified internal schema
- Maintain package-to-CVE mapping tables
- Publish new vulnerability events to NATS for incremental rescan
- Serve vulnerability lookup API for finding enrichment
- Accept offline bundle import (signed)

**Major Components:**
- `internal/vuln/service.go` — gRPC server, lookup API
- `internal/vuln/ingest/` — Feed-specific parsers (nvd, cisa_kev)
- `internal/vuln/normalizer.go` — Normalize to internal schema, dedup by CVE ID
- `internal/vuln/matcher.go` — Package version range matching (semver, PEP 440, Maven)
- `internal/vuln/offline.go` — Offline bundle import handler

**Key APIs:**
```
gRPC:
  VulnIntel.LookupByPackage(ecosystem, name, version) → []Vulnerability
  VulnIntel.LookupByCVE(cve_id) → Vulnerability
  VulnIntel.GetFeedStatus() → []FeedSyncStatus
  VulnIntel.ImportBundle(bundle_path) → ImportResult

NATS (producer):
  vuln.intelligence.new — New/updated vulnerability events
```

---

### 4.8 Rule Repository

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-rule-repo` |
| Ports | 9004 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL read/write (rules schema) |
| Dependencies | Update Manager, MinIO |

**Responsibilities:**
- Store SAST/DAST rules with semantic versioning
- Serve rules to workers via gRPC (with client-side caching)
- Support rule layering: built-in < vendor < custom
- Validate rule syntax on import
- Protect custom rules from vendor updates

**Major Components:**
- `internal/rules/service.go` — gRPC server, rule serving
- `internal/rules/import.go` — Rule import from bundles, syntax validation
- `internal/rules/resolver.go` — Rule layering resolution (custom overrides vendor)

**Key APIs:**
```
gRPC:
  RuleRepository.GetRules(engine_type, language, rule_set_ids) → []Rule
  RuleRepository.GetRuleSetVersion(rule_set_id) → Version
  RuleRepository.ImportRuleBundle(bundle_path) → ImportResult
```

---

### 4.9 Correlation Engine

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-correlator` |
| Ports | 9005 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL read/write (findings schema) |
| Dependencies | NATS, Vuln Intelligence Service |

**Responsibilities:**
- Subscribe to `scan.results.sast` and `scan.results.dast`
- Deduplicate findings within project (fingerprint-based)
- Match SAST↔DAST findings using weighted multi-signal algorithm
- Enrich findings with vulnerability intelligence
- Calculate composite risk score
- Write findings to PostgreSQL (batch insert via COPY)
- Manage finding lifecycle (first_seen, last_seen, scan_count)

**Major Components:**
- `internal/correlator/consumer.go` — NATS consumer, batch accumulator
- `internal/correlator/dedup.go` — Fingerprint-based deduplication
- `internal/correlator/matcher.go` — SAST↔DAST correlation algorithm
- `internal/correlator/scorer.go` — Composite risk scoring
- `internal/correlator/writer.go` — Batch finding writer (PostgreSQL COPY)
- `internal/correlator/enricher.go` — Vuln intel enrichment (CVSS, EPSS, KEV)

**Correlation Algorithm (from architecture review resolution):**
```
Match Score = 0.40 × cwe_match + 0.25 × parameter_match
            + 0.20 × endpoint_match + 0.15 × temporal_match

Confidence: HIGH ≥ 0.80, MEDIUM ≥ 0.50, LOW ≥ 0.30

Risk Score = CVSS_base × exploit_multiplier × asset_criticality_weight
  exploit_multiplier: 1.0 (none), 1.5 (known), 2.0 (active/CISA KEV)
  asset_criticality_weight: critical=1.5, high=1.2, medium=1.0, low=0.7
```

**Key APIs:**
```
NATS (consumer):
  scan.results.sast — Individual SAST findings
  scan.results.dast — Individual DAST findings

NATS (producer):
  findings.correlated — Correlated/enriched findings for downstream

gRPC (client):
  VulnIntel.LookupByPackage, LookupByCVE
```

---

### 4.10 Evidence Store

Not a standalone service — a shared library (`pkg/evidence`) used by SAST/DAST workers and the Reporting Service.

**Responsibilities:**
- Upload evidence artifacts to MinIO with SHA-256 integrity
- Organize by `evidence/{project_id}/{scan_id}/{finding_type}/{finding_id}/`
- Generate per-scan manifest (artifact hashes)
- Verify evidence integrity on read (Post-MVP P2-5)

**Major Components:**
- `pkg/evidence/store.go` — MinIO client, upload/download with hashing
- `pkg/evidence/manifest.go` — Scan manifest generation

---

### 4.11 Findings Store

Not a standalone service — PostgreSQL tables in the `findings` schema, accessed via the Correlation Engine (write) and Control Plane (read).

**Responsibilities:**
- Store findings with full metadata (severity, CWE, location, evidence ref)
- Track finding state transitions (immutable history)
- Store annotations
- Enforce RLS (team-scoped access)
- Database trigger prevents UPDATE on immutable core fields

**Major Components:**
- `migrations/` — Schema creation, triggers, RLS policies, indexes
- `pkg/db/findings.go` — Finding query builder, batch writer

---

### 4.12 Policy Engine

| Property | Value |
|---|---|
| Language | Go (OPA embedded) |
| Binary | `sentinelcore-policy-engine` |
| Ports | 9006 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL read (policies schema) |
| Dependencies | OPA (embedded library) |

**Responsibilities:**
- Evaluate RBAC policies (role-to-permission mapping)
- Evaluate scan scope policies (target allowlists)
- Evaluate gate policies (CI/CD pass/fail criteria)
- Cache policy bundles for low-latency evaluation
- Return allow/deny with decision reason

**MVP Scope:** Hardcoded RBAC permission matrix (no OPA). OPA/Rego in Post-MVP (P2-2).

**Failure mode:** Fail-closed for authorization checks (deny all if Policy Engine is unreachable). Fail-open for scan scope checks only when the Orchestrator already has a validated scope document from a prior successful evaluation (cached scope document has a 5-minute TTL).

**Major Components:**
- `internal/policy/service.go` — gRPC server
- `internal/policy/rbac.go` — Role-permission matrix evaluation
- `internal/policy/scope.go` — Scan target scope validation
- `internal/policy/gate.go` — CI/CD gate criteria evaluation

**Key APIs:**
```
gRPC:
  PolicyEngine.Evaluate(actor, action, resource) → Decision{allow, reason}
  PolicyEngine.EvaluateScanScope(scan_target, project) → Decision
  PolicyEngine.EvaluateGate(scan_results, gate_policy) → GateResult
```

---

### 4.13 Audit Log Service

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-audit` |
| Ports | 9007 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL append-only (audit schema) |
| Dependencies | NATS |

**Responsibilities:**
- Subscribe to audit events from NATS
- Write events to PostgreSQL (append-only, INSERT-only DB user)
- Build HMAC integrity chain (Phase 2; MVP uses sequential insertion)
- Serve audit log query API
- Manage partition creation (monthly partitions via pg_partman)

**Major Components:**
- `internal/audit/consumer.go` — NATS consumer, batch writer
- `internal/audit/query.go` — Audit log search (by actor, resource, action, time range)
- `internal/audit/integrity.go` — HMAC chain builder and verifier (Phase 2)

**Key APIs:**
```
NATS (consumer):
  audit.events — All audit events from all services

gRPC:
  AuditService.QueryLogs(filters, pagination) → []AuditEvent
  AuditService.VerifyIntegrity(time_range) → IntegrityResult (Phase 2)
```

---

### 4.14 Reporting Service

| Property | Value |
|---|---|
| Language | Go + Python (report rendering) |
| Binary | `sentinelcore-reporter` |
| Ports | 9008 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL read (findings, scans, projects) |
| Dependencies | MinIO (evidence, report storage) |

**Responsibilities:**
- Generate JSON/CSV finding exports (MVP)
- Generate PDF/HTML reports (Phase 2)
- Verify evidence integrity before including in reports (Post-MVP P2-5)
- Store generated reports in MinIO

**Major Components:**
- `internal/reporter/service.go` — gRPC server, report generation
- `internal/reporter/export.go` — JSON/CSV exporters
- `internal/reporter/pdf.go` — PDF report renderer (Phase 2, Python)

**Key APIs:**
```
gRPC:
  ReportService.ExportFindings(project_id, format, filters) → ReportRef
  ReportService.GenerateReport(report_type, params) → ReportRef (Phase 2)
  ReportService.GetReport(report_id) → ReportData
```

---

### 4.15 Update Manager

| Property | Value |
|---|---|
| Language | Go |
| Binary | `sentinelcore-updater` |
| Ports | 9009 (gRPC), 9090 (metrics) |
| DB access | PostgreSQL read/write (updates schema) |
| Dependencies | MinIO, Rule Repository, Vuln Intelligence Service |

**Responsibilities:**
- Import signed bundles (platform, rules, vuln intel)
- Full trust chain verification (Section 6.1 of trust spec — 25 steps)
- Trust store management (`/var/lib/sentinelcore/trust/`)
- Signing key certificate lifecycle
- Revocation list processing
- Lockdown mode
- Version monotonicity enforcement

**Major Components:**
- `internal/updater/service.go` — gRPC server, import workflow
- `internal/updater/verify.go` — Full 25-step bundle verification algorithm
- `internal/updater/trust.go` — Trust store management (root key, signing certs, revocations)
- `internal/updater/lockdown.go` — Lockdown flag management (DB-backed)
- `pkg/crypto/canonical.go` — Canonical JSON serialization
- `pkg/crypto/ed25519.go` — Ed25519 sign/verify wrappers

**Key APIs:**
```
gRPC:
  UpdateManager.ImportBundle(bundle_path) → ImportResult
  UpdateManager.GetTrustState() → TrustState
  UpdateManager.ListSigningCertificates() → []Certificate
  UpdateManager.EnableLockdown(reason) → Result
  UpdateManager.DisableLockdown() → Result

CLI:
  sentinelcore-cli update import --bundle <path>
  sentinelcore-cli update trust-status
  sentinelcore-cli update verify-bundle --bundle <path>
  sentinelcore-cli update pin-root-key --key <b64> --confirm-emergency
  sentinelcore-cli update lockdown --enable/--disable
  sentinelcore-cli update rollback --bundle-type <type> --to-version <v> --override-monotonicity
```

---

## 5. Development Phases

### Phase 1: Core Platform Foundation (Weeks 1–4)

**Goal:** Running infrastructure, shared libraries, Control Plane API with auth and RBAC, audit logging, database schema with RLS.

| Week | Deliverables |
|---|---|
| 1 | Repository scaffolding, Makefile, CI pipeline. Docker Compose with PostgreSQL, NATS, MinIO, Redis, Vault (dev mode). `pkg/db`: connection pool, migration runner, RLS session setup. `pkg/nats`: JetStream client. `pkg/config`: layered config loader. |
| 2 | `pkg/auth`: JWT issuer/validator, session manager (Redis). `pkg/audit`: audit event emitter. `pkg/observability`: structured logger, Prometheus metrics, health check. `pkg/grpc`: server/client scaffolding, interceptors. Database migrations for all schemas (core, scans, findings, audit, rules, vuln_intel, policies, updates, auth, cicd) — including `evidence_hash`/`evidence_size` on findings, `hmac_key_version` on audit_log, and `core.target_verifications` table. |
| 3 | Audit Log Service (NATS consumer → PostgreSQL writer). Policy Engine (hardcoded RBAC permission matrix). Control Plane REST API: auth endpoints (login, refresh, logout), project CRUD, team CRUD, user CRUD. Application-level rate limiter middleware (token bucket, Redis-backed). |
| 4 | Control Plane: scan target CRUD, finding query API, scan lifecycle API (create, get status). RLS policies enforced. Integration tests: auth flow, RBAC enforcement, team isolation. `sentinelcore-cli bootstrap` command. |

**Phase 1 Exit:** `curl` can authenticate, create a project, add a scan target, and query (empty) findings. Audit log captures all operations. Non-admin user is blocked from admin endpoints.

---

### Phase 2: Scanning Engines (Weeks 5–8)

**Goal:** SAST and DAST workers that produce real findings, with scope enforcement and evidence storage.

| Week | Deliverables |
|---|---|
| 5 | `pkg/evidence`: MinIO upload/download with SHA-256 hashing. Rule Repository service (gRPC server, rule import from JSON, rule serving). Built-in SAST rules for Java SQL injection, Python command injection, JS XSS (minimum 50 rules across 3 languages). |
| 6 | SAST Worker: NATS consumer, Git clone, language detection, AST parsing (tree-sitter), pattern matching, SCA (lockfile parsing + version range matching). Findings emitted to NATS. Evidence uploaded to MinIO. |
| 7 | Auth Session Broker (form-based login, bearer token injection, Vault credential retrieval). DAST Worker: NATS consumer, scope enforcer (domain allowlist, IP denylist, port check, redirect validation, DNS pinning), web crawler, passive analysis. Target ownership verification endpoints in Control Plane (DNS TXT, HTTP well-known, admin approval). |
| 8 | DAST Worker: active testing (SQLi, XSS, header injection payloads), HTTP trace evidence capture. SAST secret detection (entropy + regex). `pkg/nats/signing.go`: worker message signing with ephemeral keys. Integration tests: end-to-end scan of test applications. |

**Phase 2 Exit:** SAST scan of a Java project produces SQL injection findings. DAST scan of OWASP Juice Shop produces XSS/SQLi findings. DAST scope enforcer blocks requests to `127.0.0.1`. DAST scan is rejected for unverified targets. Evidence artifacts stored in MinIO with valid SHA-256 hashes. Note: SAST workers run with non-root, read-only root, no-network, resource limits — seccomp/AppArmor profiles are deferred to Phase 4 hardening (Docker Compose testing in Phase 2 does not use K8s NetworkPolicies).

---

### Phase 3: Orchestration & Intelligence (Weeks 9–12)

**Goal:** Scan orchestrator coordinates end-to-end scans. Vulnerability intelligence enriches findings. Correlation engine links SAST↔DAST.

| Week | Deliverables |
|---|---|
| 9 | Scan Orchestrator: dispatch via NATS, scan state machine, heartbeat monitoring, timeout enforcement. Dynamic NetworkPolicy creation for DAST scans. NetworkPolicy GC CronJob. Pre-dispatch target verification check. 90-day re-verification CronJob. |
| 10 | Vuln Intelligence Service: NVD JSON feed parser, CISA KEV parser, normalization, package-to-CVE mapping. Offline bundle import. Feed sync status tracking. |
| 11 | Correlation Engine: NATS consumer (SAST + DAST results) with message signature verification (reject unsigned/invalid messages), fingerprint deduplication, CWE-based SAST↔DAST matching, composite risk scoring. Batch finding writer (PostgreSQL COPY). |
| 12 | Finding enrichment with vuln intel (CVSS, KEV status). Finding immutability trigger (prevent UPDATE on core fields). Integration tests: full scan pipeline from trigger → dispatch → scan → correlate → query findings. |

**Phase 3 Exit:** A full SAST+DAST scan is orchestrated end-to-end. SAST SCA findings are enriched with NVD CVE data. A SQL injection found by both SAST and DAST is correlated with HIGH confidence. NetworkPolicies are created/destroyed per scan.

---

### Phase 4: Integration & Delivery (Weeks 13–16)

**Goal:** CI/CD integration, reporting, secure updates, deployment artifacts, end-to-end hardening.

| Week | Deliverables |
|---|---|
| 13 | CI/CD Connector: GitHub/GitLab webhook receiver with HMAC verification, scan trigger, gate policy evaluation (severity threshold). Update Manager: bundle import, full 25-step trust chain verification, trust store management, `sentinelcore-cli update` commands. |
| 14 | Reporting Service: JSON/CSV finding export. `sentinelcore-cli` full MVP commands (bootstrap, scan, trust, status). `pkg/crypto`: canonical JSON serialization, Ed25519 verification library. |
| 15 | Security hardening: TLS on all external endpoints, input validation audit, SAST worker seccomp + AppArmor profiles (applied and tested), DAST scope enforcer fuzzing, RBAC coverage verification. Break-glass emergency access (Shamir shares, `_emergency_admin` account, file-based audit, 4-hour auto-expiry). Helm chart with namespaces, NetworkPolicies, resource limits, RBAC. |
| 16 | Docker Compose deployment. End-to-end acceptance tests. Performance baseline (scan throughput, API latency). Documentation: installation guide, API reference, bootstrap guide. |

**Phase 4 Exit:** All MVP exit criteria (Section 3) met. System deploys via Docker Compose and Helm. CI/CD webhook triggers a scan that gates a pipeline.

---

### Phase 5: Enterprise Governance (Post-MVP, Phase 2 Roadmap)

**Goal:** Full RBAC with OPA, OIDC/LDAP/SAML, HMAC audit chain, SIEM export, scheduled scans, PDF reports, full vulnerability intelligence.

| Sprint | Deliverables |
|---|---|
| P2-1 (2w) | OIDC integration (Keycloak, Okta). LDAP/AD with group-to-team mapping. |
| P2-2 (2w) | OPA/Rego policy engine replacement. Policy versioning. Approval workflows. Dual-approval for global policy changes (RBAC-04). |
| P2-3 (2w) | Full vuln intel: OSV, GitHub Advisory, EPSS. Anomaly detection. Incremental rescan triggers. Cross-project finding aggregation (read-only, `security_director` role). |
| P2-4 (2w) | Scan scheduling (cron-based). Scan profiles (passive/standard/aggressive). Incremental SAST. |
| P2-5 (2w) | HMAC integrity chain on audit log. SIEM integration (syslog, HTTPS webhook, Kafka). Evidence read-time verification. |
| P2-6 (2w) | PDF report generation. Compliance mapping (SOC 2, ISO 27001). SLA tracking. Grafana dashboards. |
| P2-7 (2w) | Notification Service: webhook, email (SMTP), Slack-compatible channels. Per-team configuration. Delivery tracking with retry. |

**Deferred beyond Post-MVP:** AI Assist (local LLM-based remediation suggestions), GraphQL/WebSocket scanning, IaC scanning, custom rule DSL, multi-site replication, IDE plugins, ticket integration.

---

## 6. Infrastructure Requirements

### Databases

| Component | Technology | Purpose | MVP Config | Production Config |
|---|---|---|---|---|
| Primary DB | PostgreSQL 16 | Findings, config, audit, all structured data | Single instance, 4GB RAM | Patroni HA (Kubernetes lease-based leader election, `synchronous_mode_strict: true`), primary + 2 replicas, 16GB RAM, SSD. Trade-off: single replica failure causes write downtime — accepted for data safety. |
| Connection pooler | PgBouncer | Transaction-mode connection pooling | Embedded sidecar | Dedicated pod, max 200 connections |
| Cache | Redis 7 | JWT sessions, config cache, rate limiting | Single instance, 512MB | Sentinel, 2GB, AOF persistence |

### Object Storage

| Component | Technology | Purpose | MVP Config | Production Config |
|---|---|---|---|---|
| Evidence store | MinIO | Scan evidence, reports, rule bundles | Single instance, 50GB | Distributed (4 nodes), erasure coding, 500GB/node |
| Encryption | MinIO SSE-S3 | AES-256-GCM at rest | Vault-managed master key | Vault-managed, per-object derived keys |

### Message Queue

| Component | Technology | Purpose | MVP Config | Production Config |
|---|---|---|---|---|
| Async messaging | NATS JetStream 2.10 | Scan dispatch, results, audit events | Embedded mode, 2GB storage | 3-node cluster, R3 replication, 50GB/node |

**NATS Stream Configuration:**

| Stream | Subjects | Retention | Max Age | Replicas |
|---|---|---|---|---|
| SCANS | `scan.>` | WorkQueue | 7 days | 3 |
| FINDINGS | `scan.results.>`, `findings.>` | Limits | 7 days | 3 |
| AUDIT | `audit.>` | Limits | 30 days | 3 |
| VULN | `vuln.>` | Limits | 7 days | 3 |

### Secrets Management

| Component | Technology | Purpose |
|---|---|---|
| Secrets vault | HashiCorp Vault | Scan credentials, DB passwords, encryption keys, signing keys |
| Auth method | Kubernetes auth | Pod identity → Vault policy |
| Secret engines | KV v2, Transit, PKI, Database | Credentials, encryption-as-service, internal CA, dynamic DB creds |

### Search (Phase 2)

Not in MVP. Full-text search on findings will use PostgreSQL `tsvector` + GIN indexes initially. If search volume exceeds PostgreSQL's capability, evaluate OpenSearch as a read-only secondary index.

### Worker Infrastructure

| Worker Type | Sandbox Controls | Resources | Scaling |
|---|---|---|---|
| SAST | seccomp + AppArmor, no network, read-only root, tmpfs workspace, non-root (UID 65534) | 4 CPU, 8GB RAM, 10GB tmpfs | HPA: 1–20 pods, scale on queue depth (5 pending/worker) |
| DAST | Dynamic NetworkPolicy (approved targets only), non-root | 2 CPU, 4GB RAM, 5GB emptyDir | HPA: 1–20 pods, scale on queue depth (3 pending/worker) |

---

## 7. Deployment Model

### Docker Compose (Evaluation)

```yaml
# deploy/docker-compose/docker-compose.yml
services:
  postgres:        # PostgreSQL 16, init with all schemas
  nats:            # NATS with JetStream enabled
  minio:           # MinIO single instance
  redis:           # Redis 7
  vault:           # Vault dev mode (auto-unsealed)
  controlplane:    # sentinelcore-controlplane
  orchestrator:    # sentinelcore-orchestrator
  sast-worker:     # sentinelcore-sast-worker (1 instance)
  dast-worker:     # sentinelcore-dast-worker (1 instance)
  auth-broker:     # sentinelcore-auth-broker
  vuln-intel:      # sentinelcore-vuln-intel
  rule-repo:       # sentinelcore-rule-repo
  correlator:      # sentinelcore-correlator
  policy-engine:   # sentinelcore-policy-engine
  audit-service:   # sentinelcore-audit
  reporter:        # sentinelcore-reporter
  updater:         # sentinelcore-updater
  cicd-connector:  # sentinelcore-cicd-connector
```

**Resource requirements:** 4 vCPU, 8GB RAM, 50GB disk.
**Startup:** `docker-compose up -d && sentinelcore-cli bootstrap --admin-user admin@local`

### Kubernetes Helm Chart (Production)

```
deploy/helm/sentinelcore/
├── Chart.yaml
├── values.yaml                    # Defaults (small deployment)
├── values-production.yaml         # HA, resource limits, replicas
├── values-airgapped.yaml          # No external egress, local registry
├── templates/
│   ├── _helpers.tpl
│   ├── namespaces.yaml            # 7 namespaces
│   ├── network-policies/          # Default-deny + explicit allows
│   ├── control-plane/             # Deployment, Service, ConfigMap, RBAC
│   ├── orchestrator/
│   ├── sast-worker/               # Deployment + HPA + seccomp profile
│   ├── dast-worker/               # Deployment + HPA
│   ├── auth-broker/
│   ├── vuln-intel/
│   ├── rule-repo/
│   ├── correlator/
│   ├── policy-engine/
│   ├── audit-service/
│   ├── reporter/
│   ├── updater/
│   ├── cicd-connector/
│   ├── ingress/                   # Ingress with TLS
│   ├── monitoring/                # ServiceMonitor, PrometheusRule
│   └── jobs/
│       ├── db-init.yaml           # Schema init Job (pre-install hook)
│       ├── db-migrate.yaml        # Migration Job (pre-upgrade hook)
│       └── netpol-gc.yaml         # NetworkPolicy GC CronJob
└── sandbox/
    ├── sast-seccomp.json          # Seccomp profile for SAST workers
    └── sast-apparmor.profile      # AppArmor profile for SAST workers
```

**Installation:**
```bash
helm repo add sentinelcore https://charts.sentinelcore.example.com
helm install sentinelcore sentinelcore/sentinelcore \
  --namespace sentinelcore-system --create-namespace \
  -f values-production.yaml
# Wait for init job to complete, then:
sentinelcore-cli bootstrap --admin-user admin@example.com
```

### Air-Gapped Deployment

**Installation bundle:**
```
sentinelcore-install-1.0.0.tar.gz
├── images/                        # All container images as OCI tarballs
├── helm/sentinelcore-1.0.0.tgz   # Helm chart
├── trust/                         # Root public key + initial signing certs
├── rules/                         # Initial SAST/DAST rule packs (signed)
├── vuln-intel/                    # Initial NVD + CISA KEV bundle (signed)
├── install.sh                     # Load images → local registry, helm install
└── checksums.sha256               # SHA-256 of all files
```

**Transfer procedure:**
1. Download bundle on connected workstation, verify GPG signature
2. Transfer to air-gapped environment via approved media
3. Run `install.sh` which loads images into local Harbor registry and runs `helm install`
4. Run `sentinelcore-cli bootstrap` to establish trust and create admin
5. Import rule and vuln-intel bundles via `sentinelcore-cli update import`

---

## 8. Security Implementation Tasks

### 8.1 Secure Update Verification

| Task | Phase | Details |
|---|---|---|
| `pkg/crypto/canonical.go` | Phase 1 | Canonical JSON: sort keys lexicographically, no whitespace, UTF-8. Test vectors. |
| `pkg/crypto/ed25519.go` | Phase 1 | Ed25519 verify wrapper: sign/verify canonical bytes directly (no pre-hash). |
| Trust store init | Phase 4 | Bootstrap: read root_pubkey.json, verify signing certs, write to trust store. |
| 25-step bundle verification | Phase 4 | Full algorithm from trust spec Section 6.1. Each step is a separate, testable function. |
| Revocation processing | Phase 4 | Monotonic sequence enforcement, local storage, certificate invalidation. |
| Lockdown mode | Phase 4 | DB-backed flag (updates.trust_state), reject all bundles when active. |
| CLI commands | Phase 4 | `trust-status`, `verify-bundle`, `pin-root-key`, `lockdown`, `rollback`. |

### 8.2 Secrets Integration

| Task | Phase | Details |
|---|---|---|
| Vault Kubernetes auth | Phase 1 | ServiceAccount token → Vault policy. Each service has its own policy. |
| Dynamic database credentials | Phase 1 | Vault Database secret engine → PostgreSQL users with scoped permissions. |
| Scan credential retrieval | Phase 2 | Auth Session Broker fetches from Vault KV, never caches, audit logs access. |
| Certificate rotation | Phase 3 | cert-manager for mTLS certificates, 24-hour rotation. |

### 8.3 RBAC Enforcement

| Task | Phase | Details |
|---|---|---|
| Permission matrix | Phase 1 | 9 roles × N permissions. Hardcoded map in Policy Engine. |
| API middleware | Phase 1 | gRPC interceptor + HTTP middleware: extract JWT → resolve role → check permission. |
| Application-level rate limiter | Phase 1 | Token bucket per user (100 req/min), per team (20 scans/hour), per API key (1000 req/min). Redis-backed counters. Middleware in Control Plane. |
| Row-level security | Phase 1 | PostgreSQL RLS policies on findings, scans, projects. Session variable setup per request. |
| Resource quotas | Phase 2 | Per-team limits: concurrent scans, projects, scan targets, findings storage. |
| Dual-approval for policy changes | Phase 5 | Global policy modifications require second platform_admin approval. MVP accepts single-admin policy changes (documented risk). |

### 8.4 Target Ownership Verification (CRIT-02)

| Task | Phase | Details |
|---|---|---|
| `core.target_verifications` table | Phase 1 | Schema: verification_id, target_id, method (dns_txt/http_wellknown/admin_approval), status (pending/verified/expired/failed), token, verified_at, verified_by, expires_at. Include in Phase 1 migrations. |
| DNS TXT verification | Phase 2 | Control Plane generates token, user creates `_sentinelcore-verify.{domain} TXT "sc-verify={token}"`, Control Plane queries DNS to confirm. |
| HTTP well-known verification | Phase 2 | Control Plane generates token, user places at `https://{domain}/.well-known/sentinelcore-verify`, Control Plane fetches to confirm. |
| Manual admin approval | Phase 2 | `platform_admin` can approve targets with documented justification. Audit logged. |
| Orchestrator pre-dispatch check | Phase 3 | Orchestrator rejects DAST scans for targets where `verified_at` is NULL or `expires_at < now()`. |
| 90-day re-verification | Phase 3 | CronJob marks expired verifications. Control Plane alerts team when verification is expiring. |

### 8.5 Scope Enforcement (DAST)

| Task | Phase | Details |
|---|---|---|
| Domain allowlist check | Phase 2 | Exact match + wildcard (`*.example.com`). Reject requests to non-allowed domains. |
| IP denylist | Phase 2 | Block RFC 1918, link-local, loopback, cloud metadata (`169.254.169.254`), IPv6 equivalents. |
| DNS pinning | Phase 2 | Resolve + cache IP at scan start. Re-validate on every request. Reject if IP changed. |
| Port allowlist | Phase 2 | Only allowed ports (default 80, 443). Block all others. |
| Redirect validation | Phase 2 | Follow redirects but re-validate scope at each hop. Max 10 redirects. |
| Protocol enforcement | Phase 2 | HTTP/HTTPS only. Block FTP, gopher, file://, etc. |
| Dynamic NetworkPolicy | Phase 3 | Orchestrator creates per-scan K8s NetworkPolicy with pinned target IPs. |
| NetworkPolicy GC | Phase 3 | CronJob: delete expired policies. Orchestrator startup: reconcile orphans. |

### 8.6 Worker Message Integrity (SEC-05)

| Task | Phase | Details |
|---|---|---|
| `pkg/nats/signing.go` | Phase 2 | Message signing helper: worker signs result messages with ephemeral key derived from mTLS cert. Message includes worker_id, scan_id, timestamp. |
| Correlation Engine verification | Phase 3 | Correlation Engine verifies message signature before processing. Rejects results from unknown workers or undispatched scans. Alerts on invalid messages. |
| Orchestrator dispatch records | Phase 3 | Orchestrator records {scan_id → worker_id} mapping. Correlation Engine validates against dispatch records. |

### 8.7 Break-Glass Emergency Access (RBAC-01)

| Task | Phase | Details |
|---|---|---|
| `_emergency_admin` account | Phase 4 | Created at bootstrap, disabled by default. Local-only account. |
| Shamir share generation | Phase 4 | `sentinelcore-cli bootstrap` generates 5 break-glass Shamir shares (separate from Vault unseal shares). Printed to terminal once. |
| Emergency access CLI | Phase 4 | `sentinelcore-cli emergency-access --shares <s1> <s2> <s3>` activates `_emergency_admin` for 4 hours. Requires 3-of-5 shares. |
| File-based audit log | Phase 4 | All break-glass actions logged to append-only file on persistent volume (not PostgreSQL, which may be inaccessible). |
| Auto-expiry | Phase 4 | Break-glass session auto-expires after 4 hours, non-renewable. |

### 8.8 Data Integrity Controls

| Task | Phase | Details |
|---|---|---|
| `evidence_hash` + `evidence_size` columns | Phase 1 | Add `evidence_hash TEXT` and `evidence_size BIGINT` to `findings.findings` schema in Phase 1 migrations. |
| `hmac_key_version` column | Phase 1 | Add `hmac_key_version INTEGER` (nullable) to `audit.audit_log` in Phase 1 migrations. No code changes until Phase 5. |
| Finding immutability trigger | Phase 3 | PostgreSQL trigger prevents UPDATE on core fields: title, description, severity, cwe_id, file_path, url, code_snippet, evidence_ref, evidence_hash, fingerprint, finding_type, scan_job_id. Security-critical — include in security test suite. |

### 8.5 Worker Sandboxing (SAST)

| Task | Phase | Details |
|---|---|---|
| Non-root user | Phase 2 | UID 65534, no privileged escalation, drop all capabilities. |
| Read-only root filesystem | Phase 2 | Only tmpfs at `/tmp/scan-workspace` is writable. |
| No network egress | Phase 2 | NetworkPolicy: deny all egress except NATS (results) and MinIO (evidence). |
| Seccomp profile | Phase 4 | Custom JSON profile: allow read, write, open, close, stat, mmap, brk, futex, clone. Deny all others. |
| AppArmor profile | Phase 4 | Restrict file access to `/tmp/scan-workspace` only. |
| Resource limits | Phase 2 | CPU: 4000m, Memory: 8Gi, Ephemeral storage: 10Gi. OOM kill on exceed. |
| Wall-clock timeout | Phase 3 | Orchestrator kills pod after `timeout_seconds` (default 3600). |

---

## 9. Observability Implementation

### 9.1 Logging

| Task | Phase | Details |
|---|---|---|
| Structured JSON logger | Phase 1 | `pkg/observability/logger.go`: zerolog-based, fields: timestamp, level, service, version, trace_id, span_id. |
| Log sanitization | Phase 1 | Credential fields redacted at logger level. PII only in audit events. |
| Log levels | Phase 1 | ERROR, WARN, INFO, DEBUG. Default: INFO. DEBUG via config override (auto-revert 1h). |
| Log collection | Phase 4 | Docker Compose: stdout. K8s: Fluent Bit DaemonSet → Loki (Phase 2 dashboards). |

### 9.2 Metrics

| Task | Phase | Details |
|---|---|---|
| Prometheus client | Phase 1 | `pkg/observability/metrics.go`: metrics endpoint on :9090 for all services. |
| Platform health metrics | Phase 1 | `sentinelcore_service_up`, `_request_duration_seconds`, `_request_total`, `_error_total`. |
| Scan metrics | Phase 3 | `sentinelcore_scans_total`, `_scan_duration_seconds`, `_scan_queue_depth`, `_scan_workers_active`. |
| Security metrics | Phase 3 | `sentinelcore_scope_violation_total`, `_auth_login_total`, `_policy_evaluation_total`. |
| Trust metrics | Phase 4 | `sentinelcore_signing_cert_expiry_seconds`, `_update_verification_total`, `_trust_lockdown_active`. |
| ServiceMonitor | Phase 4 | Helm template: Prometheus ServiceMonitor per service. |

### 9.3 Tracing

| Task | Phase | Details |
|---|---|---|
| OTLP setup | Phase 2 | `pkg/observability/tracing.go`: OpenTelemetry SDK, OTLP exporter. |
| gRPC interceptor | Phase 2 | Trace propagation on all gRPC calls (W3C Trace Context). |
| NATS propagation | Phase 2 | Trace context in NATS message headers. |
| Scan lifecycle span | Phase 3 | Root span `scan.lifecycle` with child spans for validation, dispatch, execution, correlation. |

### 9.4 Alerting

| Alert | Severity | Condition | Phase |
|---|---|---|---|
| ScopeViolationDetected | CRITICAL | `scope_violation_total` increases | Phase 3 |
| AuditIntegrityFailure | CRITICAL | Integrity check mismatch | Phase 5 |
| ScanWorkerDown | HIGH | Heartbeat missing > 2 min | Phase 3 |
| BundleVerificationFailed | HIGH | Bundle verification failure | Phase 4 |
| SigningCertExpiryImminent | HIGH | Cert expires in < 30 days | Phase 4 |
| DatabaseConnectionExhausted | HIGH | Available connections < 5 | Phase 1 |
| ScanQueueBacklog | MEDIUM | Queue depth > 100 for > 10 min | Phase 3 |
| VulnFeedSyncFailed | MEDIUM | Feed sync failed > 24h | Phase 3 |

---

## 10. Testing Strategy

### 10.1 Unit Tests

**Coverage target:** 80% line coverage on business logic (`internal/`), 90% on crypto (`pkg/crypto/`).

| Package | Key test scenarios |
|---|---|
| `pkg/crypto/canonical` | Canonical JSON: key ordering, nested objects, arrays, Unicode, empty objects, null values. Golden test vectors matching Go ↔ Python output. |
| `pkg/crypto/ed25519` | Sign + verify round-trip. Reject tampered signature. Reject wrong key. |
| `pkg/auth` | JWT issue + validate. Expired token rejection. Role extraction. |
| `pkg/db` | Migration up/down. RLS enforcement (query as user A, assert no user B data). |
| `internal/dast/scope` | Allowlist match. Wildcard match. Private IP rejection (all RFC 1918, link-local, loopback, metadata). DNS rebinding detection. Redirect chain validation. Port blocking. |
| `internal/correlator/matcher` | CWE exact match, parent match, no match. Parameter matching. Endpoint cosine similarity. Temporal decay. Edge cases: missing fields, no DAST findings. |
| `internal/correlator/scorer` | Risk score calculation. Exploit multiplier. Asset criticality weights. |
| `internal/updater/verify` | Each of the 25 verification steps as an independent test. Happy path. Each failure mode. |

### 10.2 Integration Tests

**Infrastructure:** `pkg/testutil` provides:
- `testutil.NewTestDB()` — Spins up PostgreSQL in Docker, runs migrations, returns connection pool
- `testutil.NewTestNATS()` — In-process NATS server with JetStream
- `testutil.NewTestMinIO()` — MinIO in Docker or mock

| Test Suite | What it validates |
|---|---|
| `test/integration/scan_pipeline_test.go` | Trigger scan → Orchestrator dispatches → Worker produces findings → Correlation writes to DB → Control Plane returns findings via API |
| `test/integration/auth_rbac_test.go` | Login → get JWT → access allowed endpoint → access denied endpoint → RLS prevents cross-team data access |
| `test/integration/dast_scope_test.go` | DAST worker with scope document → crawl allowed domain → attempt out-of-scope request → verify blocked + audit logged |
| `test/integration/update_trust_test.go` | Import valid bundle → verify acceptance. Import tampered bundle → verify rejection. Import with revoked cert → verify rejection. |
| `test/integration/cicd_gate_test.go` | Webhook trigger → scan completes → gate evaluates → returns pass/fail |
| `test/integration/audit_completeness_test.go` | Perform N operations → query audit log → assert N events with correct actors and resources |
| `test/integration/target_verification_test.go` | Create unverified target → attempt DAST scan → verify rejected. Complete DNS verification → attempt scan → verify accepted. Wait 90 days (mock clock) → verify re-verification required. |
| `test/integration/rate_limit_test.go` | Send 200 requests in 1 minute as single user → verify requests beyond 100 are rejected with 429. Verify per-team scan creation limit enforced. |
| `test/integration/message_signing_test.go` | Worker sends signed finding → Correlation Engine accepts. Send unsigned finding → Correlation Engine rejects. Send finding for undispatched scan_id → Correlation Engine rejects. |

### 10.3 Security Tests

| Test | What it validates | Phase |
|---|---|---|
| DAST scope escape | Worker attempts to reach `127.0.0.1`, `169.254.169.254`, `10.0.0.0/8` — all blocked | Phase 2 |
| DNS rebinding simulation | Target resolves to public IP, then rebinds to `127.0.0.1` — blocked by DNS pinning | Phase 3 |
| Bundle signature tampering | Modify one byte of a signed bundle — verification rejects | Phase 4 |
| Certificate substitution | Replace signing cert with a different valid cert — verification rejects (serial mismatch) | Phase 4 |
| Revoked key acceptance | Sign bundle with revoked key — verification rejects after revocation list update | Phase 4 |
| Unverified target scan | Trigger DAST scan against target with `verified_at = NULL` — Orchestrator rejects | Phase 3 |
| Rate limit bypass | Send requests exceeding rate limit — verify all excess requests get 429 | Phase 1 |
| Worker message forgery | Inject unsigned finding into NATS `scan.results.sast` — Correlation Engine rejects | Phase 3 |
| Break-glass abuse | Attempt emergency-access with fewer than 3 shares — rejected | Phase 4 |
| RBAC bypass | Attempt every admin endpoint as every non-admin role — all return 403 | Phase 1 |
| RLS bypass | Direct PostgreSQL query as team A user — assert zero rows from team B | Phase 1 |
| SAST sandbox escape | Attempt network egress from SAST worker pod — verify NetworkPolicy blocks | Phase 4 |
| Credential leakage | Trigger DAST scan, grep all logs for credential values — assert zero matches | Phase 2 |

### 10.4 Simulated Attack Tests

Run these quarterly and before major releases:

| Scenario | Attack vector | Expected result |
|---|---|---|
| **SSRF via DAST** | Configure scan target that redirects to cloud metadata endpoint | Scope enforcer blocks at redirect validation |
| **Supply chain hijack** | Present bundle with attacker-signed manifest + valid-looking cert | Verification rejects: cert not signed by pinned root |
| **Privilege escalation** | Compromised `developer` JWT used to create `platform_admin` user | Policy Engine denies: insufficient role |
| **Audit tampering** | Direct SQL UPDATE on `audit.audit_log` table | INSERT-only DB user prevents modification |
| **Finding mutation** | Direct SQL UPDATE on `findings.findings` core fields | Database trigger rejects UPDATE on immutable columns |
| **Worker breakout** | Malicious repository with code that attempts syscalls beyond seccomp allow-list | Process killed by seccomp, scan fails, alert triggered |

---

## 11. Estimated Engineering Complexity

### Easiest Components

| Component | Why it's straightforward | Estimated effort |
|---|---|---|
| Audit Log Service | NATS consumer → batch INSERT into PostgreSQL. Well-defined schema. | 3 days |
| Rule Repository | gRPC CRUD over PostgreSQL rules table. Import from JSON bundles. | 4 days |
| Evidence Store (`pkg/evidence`) | MinIO client wrapper with SHA-256 hashing. ~200 lines. | 2 days |
| Policy Engine (MVP) | Hardcoded role-permission map. ~500 lines. No OPA yet. | 3 days |
| Reporting Service (MVP) | JSON/CSV export from PostgreSQL query. | 3 days |
| Auth Session Broker | gRPC server, 3-4 auth provider implementations, Vault client. | 5 days |

### Hardest Components

| Component | Why it's hard | Estimated effort | Key risks |
|---|---|---|---|
| **DAST Scope Enforcer** | Must be bulletproof — a bypass is a critical vulnerability. DNS pinning, redirect chains, IP classification, edge cases (IPv6, dual-stack, URL parsing) | 10 days | IPv6 edge cases, URL parsing bugs, DNS TTL handling |
| **SAST Taint Analysis** | Interprocedural data flow analysis across multiple languages. Requires per-language AST understanding. False positive tuning. | 20 days | Language-specific edge cases, performance on large codebases, call graph depth |
| **Correlation Engine Matcher** | Multi-signal weighted matching algorithm. URL-to-route mapping heuristics. False correlation tuning. | 8 days | Endpoint matching accuracy, handling partial data |
| **Update Manager (Trust Chain)** | 25-step verification, canonical JSON, revocation processing, trust store management, lockdown. Security-critical — bugs are vulnerabilities. | 12 days | Canonical JSON edge cases, state machine correctness |
| **Scan Orchestrator** | Distributed state machine. Worker lifecycle management. NetworkPolicy CRUD. Timeout/retry/failure handling. Leader election. | 12 days | Race conditions, orphaned resources, Kubernetes API reliability |
| **Vulnerability Intelligence Matcher** | Version range parsing across 8 package ecosystems, each with different semver dialects. | 8 days | Version range edge cases (Maven ranges, PEP 440 pre-releases, Go pseudo-versions) |

### Major Technical Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Canonical JSON inconsistency** between Go and Python | Signature verification fails in mixed-language environments | Golden test vectors verified by both Go and Python implementations. CI runs cross-language verification. |
| **SAST performance on large codebases** | Scan timeout on repos > 500K LOC | Per-file analysis timeout. Incremental SAST (Phase 2). File size/count limits. Early benchmarking against large open-source projects. |
| **DAST scope enforcer bypass** | Unauthorized scanning of internal infrastructure | Dedicated security test suite. Fuzz testing on URL parser. Defense-in-depth with Kubernetes NetworkPolicy. Bug bounty consideration. |
| **PostgreSQL write throughput under heavy scan load** | Findings insertion becomes bottleneck | Batch INSERT via COPY protocol. NATS as write-ahead buffer. Measure early with load tests at 100 concurrent scans. |
| **Kubernetes NetworkPolicy race condition** | DAST worker starts before NetworkPolicy is applied | Orchestrator waits for NetworkPolicy to be observed by CNI before dispatching worker. Health check on policy existence. |
| **Vault availability** | Vault sealed/unreachable blocks all credential-dependent operations | Graceful degradation: SAST scans proceed (no credentials needed). DAST scans queue until Vault is available. Health check includes Vault status. |
| **NATS message ordering** | Findings arrive out of order, correlation produces inconsistent results | Correlation Engine processes findings as a set per scan_id (accumulate until scan.completed event). Not dependent on message ordering. |

---

## Appendix A: Phase-Specific Implementation Plans

Each phase will produce its own detailed, task-level implementation plan before development begins:

| Plan | Scope | Status |
|---|---|---|
| `2026-03-XX-phase1-core-platform.md` | Weeks 1–4: Infrastructure, shared libs, Control Plane, Auth, RBAC, Audit | Not yet written |
| `2026-03-XX-phase2-scan-engines.md` | Weeks 5–8: SAST, DAST, Rule Repo, Auth Broker, Evidence | Not yet written |
| `2026-03-XX-phase3-orchestration-intel.md` | Weeks 9–12: Orchestrator, Vuln Intel, Correlation, Enrichment | Not yet written |
| `2026-03-XX-phase4-integration-delivery.md` | Weeks 13–16: CI/CD, Reporting, Updates, Helm, Security Hardening | Not yet written |
| `2026-03-XX-phase5-enterprise.md` | Post-MVP: OIDC, OPA, Full Vuln Intel, SIEM, PDF Reports | Not yet written |

Each phase plan follows the writing-plans skill format: exact file paths, TDD steps, test commands, commit points.

---

## Appendix B: Cross-Reference to Architecture Documents

| Engineering Plan Section | Architecture Document(s) |
|---|---|
| Service implementation (Section 4) | `05-service-architecture.md` |
| MVP scope (Section 3) | `17-mvp-scope.md` |
| Phase 5 / Post-MVP roadmap (Section 5, Phase 5) | `18-phase2-roadmap.md` |
| Infrastructure (Section 6) | `04-high-level-architecture.md`, `13-deployment-topology.md` |
| Deployment (Section 7) | `13-deployment-topology.md`, `14-airgapped-deployment.md` |
| Security tasks (Section 8) | `07-security-architecture.md`, trust architecture spec |
| Observability (Section 9) | `08-logging-audit-observability.md` |
| RBAC (Section 8.3) | `09-rbac-authorization.md` |
| Vulnerability intel (Section 4.7) | `11-vulnerability-intelligence.md` |
| Updates (Section 4.15) | `12-update-distribution.md`, trust architecture spec |
| Risks (Section 11) | `19-risks-tradeoffs.md` |
| Compliance requirements | `10-compliance.md` |
| Scaling (Section 6) | `16-operations-scaling.md` |
| DR | `15-disaster-recovery.md` |
| Architecture review gaps | `ARCHITECTURE-REVIEW.md` |
