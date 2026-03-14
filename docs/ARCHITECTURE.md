# SentinelCore Security Platform — Architecture Specification

**Version:** 1.1.0-DRAFT
**Classification:** INTERNAL — ARCHITECTURE
**Date:** 2026-03-14

---

## Document Index

| # | Section | Location |
|---|---|---|
| 1 | [Executive Summary](architecture/01-executive-summary.md) | `docs/architecture/` |
| 2 | [Functional Requirements](architecture/02-functional-requirements.md) | `docs/architecture/` |
| 3 | [Non-Functional Requirements](architecture/03-nonfunctional-requirements.md) | `docs/architecture/` |
| 4 | [High-Level Architecture](architecture/04-high-level-architecture.md) | `docs/architecture/` |
| 5 | [Service Architecture](architecture/05-service-architecture.md) | `docs/architecture/` |
| 6 | [Data Model](data-model/06-data-model.md) | `docs/data-model/` |
| 7 | [Security Architecture](security/07-security-architecture.md) | `docs/security/` |
| 8 | [Logging, Audit, and Observability](security/08-logging-audit-observability.md) | `docs/security/` |
| 9 | [RBAC and Authorization Model](security/09-rbac-authorization.md) | `docs/security/` |
| 10 | [Compliance Considerations](architecture/10-compliance.md) | `docs/architecture/` |
| 11 | [Vulnerability Intelligence Architecture](architecture/11-vulnerability-intelligence.md) | `docs/architecture/` |
| 12 | [Update Distribution Architecture](architecture/12-update-distribution.md) | `docs/architecture/` |
| 13 | [Deployment Topology](deployment/13-deployment-topology.md) | `docs/deployment/` |
| 14 | [Air-Gapped Deployment Model](deployment/14-airgapped-deployment.md) | `docs/deployment/` |
| 15 | [Disaster Recovery Strategy](operations/15-disaster-recovery.md) | `docs/operations/` |
| 16 | [Operations and Scaling](operations/16-operations-scaling.md) | `docs/operations/` |
| 17 | [MVP Scope](architecture/17-mvp-scope.md) | `docs/architecture/` |
| 18 | [Phase 2 Roadmap](architecture/18-phase2-roadmap.md) | `docs/architecture/` |
| 19 | [Major Risks and Design Tradeoffs](architecture/19-risks-tradeoffs.md) | `docs/architecture/` |
| R | [Architecture Review](ARCHITECTURE-REVIEW.md) | `docs/` |
| 20 | [Architecture Remediation](architecture/20-architecture-remediation.md) | `docs/architecture/` |

---

## Architecture Summary

SentinelCore is a customer-managed application security platform combining SAST, DAST, and vulnerability intelligence analysis. Key architectural decisions:

- **16 core services** organized in four tiers: control plane, data processing, scan execution, and data persistence
- **Go + Python** implementation with PostgreSQL, MinIO, NATS JetStream, and Redis
- **Kubernetes-native** deployment with Helm charts; Docker Compose for evaluation
- **Air-gapped first** — every feature works offline; online is an optimization
- **Zero trust** — mTLS everywhere, OPA policy enforcement, database-level RLS
- **Tamper-evident audit** — HMAC chain integrity on all audit records
- **Ed25519 signed updates** — cryptographic verification of all platform, rule, and feed updates
- **Multi-layer scope enforcement** — application + NetworkPolicy + DNS validation prevents DAST scope escape

## Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│                    SentinelCore Platform                         │
│                                                                  │
│  Control Plane ──► Scan Orchestrator ──► SAST/DAST Workers      │
│       │                   │                    │                  │
│       ▼                   ▼                    ▼                  │
│  Policy Engine    Auth Session Broker    Evidence Store           │
│       │                   │                    │                  │
│       ▼                   ▼                    ▼                  │
│  CI/CD Connector  Vuln Intel Service    Correlation Engine       │
│       │                   │                    │                  │
│       ▼                   ▼                    ▼                  │
│  Reporting Svc    Rule Repository       Findings Store           │
│       │                   │                    │                  │
│       ▼                   ▼                    ▼                  │
│  Audit Log Svc    Update Manager        AI Assist (optional)    │
│                                                                  │
│  ═══════════════════════════════════════════════════════════     │
│  PostgreSQL │ MinIO │ NATS JetStream │ Redis │ Vault            │
└─────────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Kubernetes / k3s / Docker Compose |
| Languages | Go (services), Python (analysis, reports) |
| Database | PostgreSQL 16 with RLS |
| Object Store | MinIO (S3-compatible) |
| Message Queue | NATS JetStream |
| Cache | Redis / Valkey |
| Secrets | HashiCorp Vault |
| Policy | OPA (Open Policy Agent) |
| Observability | OpenTelemetry, Prometheus, Grafana, Loki |
| API | gRPC (internal), REST OpenAPI 3.1 (external) |
| Auth | OIDC / LDAP / SAML 2.0 / local |
