# 18. Phase 2 Roadmap

## 18.1 Phase 2 Overview

Phase 2 builds on the MVP foundation to deliver enterprise-grade capabilities: full identity integration, advanced policy engine, comprehensive reporting, and operational maturity.

**Target timeline:** 12 weeks after MVP completion

## 18.2 Phase 2 Deliverables

### 18.2.1 Identity and Access Management

| Feature | Description |
|---|---|
| OIDC integration | Support Keycloak, Okta, Azure AD, Google Workspace |
| LDAP/AD integration | Bind authentication, group-to-team mapping |
| SAML 2.0 | Enterprise SSO federation |
| Multi-organization | Org-level isolation with org admin roles |
| Full RBAC with OPA | Policy-as-code, custom roles, approval workflows |
| API key management | Scoped tokens with IP restriction and expiry |

### 18.2.2 Advanced Scanning

| Feature | Description |
|---|---|
| Full language matrix | Add C#, Go, Ruby, PHP, C/C++ support to SAST |
| API security testing | OpenAPI/Swagger-driven DAST scanning |
| OAuth2 authentication | Client credentials and auth code flows in Auth Broker |
| Scan scheduling | Cron-based recurring scans with timezone support |
| Scan profiles | Pre-configured scan profiles (passive, standard, aggressive) |
| Incremental SAST | Diff-based scanning on changed files only |
| Checkpoint resume | Resume interrupted DAST scans from last checkpoint |

### 18.2.3 Vulnerability Intelligence (Full)

| Feature | Description |
|---|---|
| All 5 feeds | Add OSV, GitHub Advisory Database, EPSS to existing NVD + CISA KEV |
| EPSS scoring | Exploit prediction scoring on all findings |
| Incremental rescan | Auto-trigger rescans when new CVEs match project dependencies |
| Anomaly detection | Detect suspicious changes in vulnerability feed data |

### 18.2.4 Policy Engine (Full)

| Feature | Description |
|---|---|
| OPA/Rego policies | Custom policy authoring with Rego DSL |
| Gate policies | CI/CD gate criteria (severity threshold, CWE blocklist, scan coverage) |
| Policy versioning | Version history, rollback, diff comparison |
| Policy inheritance | Organization → team → project policy cascade |
| Approval workflows | Multi-party approval for scope changes and risk acceptance |

### 18.2.5 Reporting and Compliance

| Feature | Description |
|---|---|
| PDF reports | Professional PDF generation with customizable templates |
| Scheduled reports | Automatic report generation on configurable schedule |
| Trend analysis | Vulnerability trend charts across scan history |
| Compliance mapping | SOC 2, ISO 27001, PCI DSS control evidence mapping |
| SLA tracking | Time-to-remediation tracking with SLA breach alerts |

### 18.2.6 Operational Maturity

| Feature | Description |
|---|---|
| SIEM integration | Real-time audit log streaming (syslog, HTTPS, Kafka) |
| Audit integrity chain | HMAC-SHA256 chain with hourly verification |
| Backup automation | Automated daily backups with verification |
| DR automation | One-command restore, automated DR drills |
| Grafana dashboards | Pre-built dashboards for all operational metrics |
| Alert rules | Pre-configured Prometheus alert rules |

### 18.2.7 Update Management (Full)

| Feature | Description |
|---|---|
| Online pull | Automatic check and download of updates (connected mode) |
| Rule update pipeline | Separate rule update lifecycle from platform updates |
| Rollback automation | One-command rollback with automatic pre-upgrade snapshots |
| Update preview | Dry-run mode showing what will change before applying |

## 18.3 Phase 3 (Future)

| Feature | Description | Timeline |
|---|---|---|
| AI Assist | Local LLM integration for finding analysis and remediation | Phase 3 (Q3) |
| GraphQL scanning | DAST support for GraphQL endpoints | Phase 3 (Q3) |
| WebSocket scanning | DAST support for WebSocket protocols | Phase 3 (Q4) |
| IaC scanning | Terraform, CloudFormation, Helm chart analysis | Phase 3 (Q3) |
| Custom rule DSL | User-authored SAST/DAST rules with IDE support | Phase 3 (Q4) |
| Multi-site replication | Active-passive replication across data centers | Phase 3 (Q4) |
| Event-driven notifications | Webhook/email notifications for finding lifecycle events | Phase 3 (Q3) |
| IDE plugins | VS Code, IntelliJ plugins for inline finding display | Phase 4 |
| Ticket integration | Jira, ServiceNow, Azure DevOps ticket creation from findings | Phase 4 |
| Risk scoring model | ML-based risk scoring combining multiple signals | Phase 4 |

## 18.4 Phase 2 Milestones

| Week | Milestone | Deliverables |
|---|---|---|
| 1–2 | Identity | OIDC/LDAP integration, multi-org support |
| 3–4 | Policy Engine | OPA integration, Rego policy authoring, policy versioning |
| 5–6 | Advanced Scanning | API testing, OAuth2 auth, scan scheduling |
| 7–8 | Full Vuln Intel | All 5 feeds, EPSS, incremental rescan triggers |
| 9–10 | Reporting | PDF generation, templates, trend analysis, compliance mapping |
| 11 | Operations | SIEM integration, backup automation, dashboards |
| 12 | Hardening | Security review, performance testing, documentation |
