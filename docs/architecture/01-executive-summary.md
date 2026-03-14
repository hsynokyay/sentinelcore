# 1. Executive Summary

## SentinelCore Security Platform — Architecture Specification

**Version:** 1.0.0-DRAFT
**Classification:** INTERNAL — ARCHITECTURE
**Date:** 2026-03-14

---

## 1.1 Purpose

SentinelCore is an enterprise-grade, customer-managed application security platform that unifies Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), and vulnerability intelligence-driven analysis into a single, self-contained system. It is designed to run entirely within a customer's infrastructure — on-premises data centers, private cloud environments, or fully air-gapped networks — with zero external data leakage.

## 1.2 Problem Statement

Enterprise security teams face fragmented toolchains: separate SAST scanners, DAST tools, vulnerability databases, and reporting systems that do not share context. This fragmentation leads to:

- **Duplicate findings** across tools with no correlation
- **Missed vulnerabilities** where SAST and DAST findings compound but are not linked
- **Operational overhead** managing multiple scan pipelines, credential stores, and update mechanisms
- **Compliance gaps** from inconsistent audit trails across disparate systems
- **Deployment constraints** where cloud-dependent tools cannot operate in restricted environments

## 1.3 Solution Overview

SentinelCore addresses these problems through:

1. **Unified Scan Orchestration** — A single control plane that schedules, dispatches, and monitors both SAST and DAST scans across distributed workers.
2. **Correlation Engine** — Automatic linking of SAST findings (code-level) with DAST findings (runtime-level) to produce high-confidence, deduplicated vulnerability reports.
3. **Vulnerability Intelligence Service** — Ingestion and normalization of public vulnerability feeds (NVD, CVE, OSV, GitHub Advisory Database, CISA KEV) to enrich findings with known exploit data, severity scoring, and remediation guidance.
4. **Air-Gap Ready Architecture** — Every component operates offline. Updates, rules, and vulnerability feeds are delivered via cryptographically signed bundles.
5. **CI/CD Native Integration** — First-class connectors for Jenkins, GitLab CI, GitHub Actions, Azure DevOps, and generic webhook-based pipelines.
6. **Strict Scope Enforcement** — Domain allowlists, network boundary controls, and scan target validation ensure DAST testing never escapes authorized targets.
7. **Full Auditability** — Every action, configuration change, scan execution, and data access is logged to an append-only audit log with tamper-evident integrity verification.

## 1.4 Key Design Principles

| Principle | Description |
|---|---|
| **Zero Trust by Default** | All internal service communication is mutually authenticated and encrypted. No implicit trust between components. |
| **Data Sovereignty** | All data remains within the customer's infrastructure boundary. No telemetry, no phone-home, no external dependencies at runtime. |
| **Defense in Depth** | Multiple layers of access control, encryption, scope enforcement, and audit logging. |
| **Offline First** | The system is designed for air-gapped operation as the primary mode. Online connectivity is an optimization, not a requirement. |
| **Minimal Privilege** | Every component runs with the least privilege required. Scan workers cannot access the control plane database. The DAST engine cannot scan targets not in the approved scope. |
| **Auditability Over Convenience** | Every state transition is logged. Configuration changes require approval workflows. Scan results are immutable once written. |
| **Horizontal Scalability** | Scan workers scale independently. The control plane remains stateless where possible. Queue-based dispatch decouples producers from consumers. |
| **Operational Simplicity** | Kubernetes-native deployment with Helm charts. Single-binary worker option for constrained environments. Health checks, readiness probes, and structured logging throughout. |

## 1.5 Deployment Models

SentinelCore supports three deployment tiers:

- **Connected Mode** — Full internet access. Vulnerability feeds and rule updates are pulled directly from upstream sources.
- **Semi-Connected Mode** — Outbound access to specific feed endpoints only. All other traffic is blocked.
- **Air-Gapped Mode** — No network connectivity. All updates arrive via signed offline bundles transferred through approved media.

## 1.6 Technology Stack Summary

| Layer | Technology |
|---|---|
| Runtime | Kubernetes (k8s) / k3s for edge deployments |
| Languages | Go (control plane, orchestrator, engines), Python (analysis tooling, rule evaluation) |
| Message Queue | NATS JetStream (embedded, no external dependency) |
| Primary Database | PostgreSQL 16 with row-level security |
| Document Store | MinIO (S3-compatible, self-hosted) for evidence and artifacts |
| Cache | Redis (embedded mode) or Valkey |
| Secret Management | HashiCorp Vault integration / built-in sealed secret store |
| Observability | OpenTelemetry → Prometheus + Grafana (bundled) |
| API | gRPC (internal), REST/OpenAPI 3.1 (external) |
| Authentication | OIDC / LDAP / SAML 2.0 / local accounts |
| Authorization | OPA (Open Policy Agent) with Rego policies |

## 1.7 Audience

This document is intended for:

- Security architects evaluating SentinelCore for enterprise deployment
- Platform engineers responsible for installation, configuration, and operations
- Compliance officers assessing audit and governance capabilities
- Development leads integrating SentinelCore into CI/CD pipelines
