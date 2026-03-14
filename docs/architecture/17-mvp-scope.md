# 17. MVP Scope

## 17.1 MVP Definition

The Minimum Viable Product delivers a functional, secure, end-to-end scanning platform supporting the core use case: **CI/CD-triggered SAST and DAST scanning with vulnerability correlation and basic reporting**.

**Target timeline:** 16 weeks from project start

## 17.2 MVP Components

### 17.2.1 In Scope (MVP)

| Component | MVP Capability | Full Capability (Post-MVP) |
|---|---|---|
| **Control Plane** | REST API, project/scan CRUD, local auth | OIDC/LDAP/SAML, full admin UI |
| **Scan Orchestrator** | Basic scan dispatch, single-phase scans | Multi-phase scans, scheduling, checkpoint resume |
| **SAST Engine** | Java, Python, JavaScript analysis; SCA; secret detection | Full language matrix, IaC scanning, custom rules DSL |
| **DAST Engine** | Web app scanning, form-based auth, scope enforcement | Full auth types, API testing, GraphQL, WebSocket |
| **Auth Session Broker** | Form-based login, bearer token injection | OAuth2 flows, scripted auth, credential rotation |
| **CI/CD Connector** | Webhook trigger, basic pass/fail gate | Full platform integrations, PR comments, scan profiles |
| **Vuln Intel Service** | NVD + CISA KEV ingestion (online + offline) | All 5 feeds, EPSS, incremental rescan triggering |
| **Rule Repository** | Built-in rules, rule loading | Versioned updates, custom rules, rule overlays |
| **Correlation Engine** | CWE-based correlation, basic dedup | Full multi-axis correlation, composite risk scoring |
| **Evidence Store** | MinIO storage with SHA-256 integrity | WORM lock, Merkle tree integrity, evidence export |
| **Findings Store** | Basic CRUD, severity filtering | Full lifecycle, RLS, annotations, trend tracking |
| **Policy Engine** | Hardcoded RBAC, basic scan scope validation | OPA/Rego policies, gate policies, policy versioning |
| **Audit Log Service** | Structured audit events to PostgreSQL | HMAC chain, SIEM export, integrity verification |
| **Reporting Service** | JSON/CSV export of findings | PDF reports, templates, scheduled reports, trends |
| **Update Manager** | Signed bundle import (offline) | Online pull, automatic verification, rollback |
| **AI Assist** | Not included | Optional LLM integration |

### 17.2.2 Out of Scope (MVP)

- Advanced UI (API-first approach; basic admin UI for configuration only)
- OIDC/LDAP/SAML integration (local auth only in MVP)
- Multi-organization support (single org in MVP)
- Scan scheduling (on-demand and CI/CD trigger only)
- GraphQL and WebSocket scanning
- IaC scanning
- Custom rule DSL
- OPA policy-as-code (hardcoded policies in MVP)
- PDF report generation
- SIEM integration
- AI Assist module
- Multi-site replication

## 17.3 MVP Architecture

### 17.3.1 Simplified Deployment

MVP supports Docker Compose deployment for rapid adoption:

```yaml
# docker-compose.yml (MVP evaluation deployment)
services:
  controlplane:
    image: sentinelcore/controlplane:mvp
    ports: ["8080:8080"]
    depends_on: [postgres, nats, minio, redis]

  orchestrator:
    image: sentinelcore/orchestrator:mvp
    depends_on: [controlplane, nats]

  sast-worker:
    image: sentinelcore/sast-worker:mvp
    depends_on: [nats, minio]

  dast-worker:
    image: sentinelcore/dast-worker:mvp
    depends_on: [nats, minio]
    # Scope enforcement active even in MVP

  auth-broker:
    image: sentinelcore/auth-broker:mvp
    depends_on: [controlplane]

  cicd-connector:
    image: sentinelcore/cicd-connector:mvp
    ports: ["8081:8081"]
    depends_on: [controlplane]

  vuln-intel:
    image: sentinelcore/vuln-intel:mvp
    depends_on: [postgres, nats]

  correlation:
    image: sentinelcore/correlator:mvp
    depends_on: [postgres, nats]

  audit:
    image: sentinelcore/audit:mvp
    depends_on: [postgres, nats]

  postgres:
    image: postgres:16
    volumes: [pgdata:/var/lib/postgresql/data]

  nats:
    image: nats:2.10
    command: ["-js"]

  minio:
    image: minio/minio:latest
    command: ["server", "/data"]
    volumes: [miniodata:/data]

  redis:
    image: redis:7
    volumes: [redisdata:/data]
```

### 17.3.2 MVP Security Non-Negotiables

Even in MVP, the following security controls are mandatory:

- Scan scope enforcement (DAST domain allowlist)
- TLS for all external-facing endpoints
- Credential isolation (no plaintext credentials in config or logs)
- Audit logging of all scan operations
- Ed25519 signature verification on update bundles
- Input validation on all API endpoints
- Anti-SSRF controls in DAST worker

## 17.4 MVP Milestones

| Week | Milestone | Deliverables |
|---|---|---|
| 1–2 | Foundation | PostgreSQL schema, NATS setup, MinIO setup, project scaffolding |
| 3–4 | Control Plane | REST API, project CRUD, local auth, basic RBAC |
| 5–6 | SAST Engine | Java + Python analysis, SCA, secret detection, SARIF output |
| 7–8 | DAST Engine | Web crawling, scope enforcement, form-based auth, passive + active scanning |
| 9–10 | Orchestration | Scan dispatch, worker communication, progress tracking, basic retry |
| 11–12 | Intelligence | NVD + CISA KEV ingestion, finding correlation, dedup |
| 13–14 | Integration | CI/CD webhook, pass/fail gates, findings API, evidence storage |
| 15 | Security Hardening | Audit logging, signed updates, credential handling, scope enforcement testing |
| 16 | Integration Testing | End-to-end testing, documentation, Docker Compose packaging |

## 17.5 MVP Acceptance Criteria

1. A CI/CD pipeline can trigger a SAST scan on a Java or Python repository and receive pass/fail result
2. A CI/CD pipeline can trigger a DAST scan on a web application with form-based auth and receive pass/fail result
3. DAST scope enforcement prevents scanning outside approved domains
4. SAST findings and DAST findings for the same vulnerability are correlated
5. Findings are enriched with NVD CVE data
6. All scan operations produce audit log entries
7. Update bundles with invalid signatures are rejected
8. The system operates with no external network dependencies (offline mode tested)
9. Scan credentials are never exposed in logs or API responses
10. Platform deploys successfully via Docker Compose and Helm chart
