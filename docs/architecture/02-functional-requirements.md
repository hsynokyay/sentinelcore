# 2. Functional Requirements

## 2.1 Scan Management

| ID | Requirement | Priority |
|---|---|---|
| FR-SM-001 | System SHALL support on-demand scan initiation via API and UI | P0 |
| FR-SM-002 | System SHALL support scheduled scans with cron-compatible expressions | P0 |
| FR-SM-003 | System SHALL support CI/CD-triggered scans via webhook or connector | P0 |
| FR-SM-004 | System SHALL support concurrent execution of multiple scans across isolated workers | P0 |
| FR-SM-005 | System SHALL enforce scan target scope validation before any DAST scan begins | P0 |
| FR-SM-006 | System SHALL support scan cancellation with graceful worker shutdown | P0 |
| FR-SM-007 | System SHALL support scan pause and resume for long-running DAST scans | P1 |
| FR-SM-008 | System SHALL support incremental SAST scans on changed files only (diff-based) | P0 |
| FR-SM-009 | System SHALL support incremental rescanning when new vulnerability signatures appear | P0 |
| FR-SM-010 | System SHALL track scan progress with percentage completion and phase indicators | P0 |

## 2.2 SAST Engine

| ID | Requirement | Priority |
|---|---|---|
| FR-SAST-001 | Engine SHALL perform static analysis on source code repositories | P0 |
| FR-SAST-002 | Engine SHALL support languages: Java, Python, JavaScript/TypeScript, Go, C#, Ruby, PHP, C/C++ | P0 |
| FR-SAST-003 | Engine SHALL perform taint analysis to trace data flow from sources to sinks | P0 |
| FR-SAST-004 | Engine SHALL detect OWASP Top 10 vulnerability categories | P0 |
| FR-SAST-005 | Engine SHALL support custom rule definitions in a documented DSL | P0 |
| FR-SAST-006 | Engine SHALL perform Software Composition Analysis (SCA) on declared dependencies | P0 |
| FR-SAST-007 | Engine SHALL detect hardcoded secrets and credentials | P0 |
| FR-SAST-008 | Engine SHALL generate code-location-precise findings with file, line, and column references | P0 |
| FR-SAST-009 | Engine SHALL support analysis of Infrastructure-as-Code (Terraform, CloudFormation, Helm) | P1 |
| FR-SAST-010 | Engine SHALL produce SARIF-formatted output | P0 |

## 2.3 DAST Engine

| ID | Requirement | Priority |
|---|---|---|
| FR-DAST-001 | Engine SHALL perform authenticated scanning of web applications | P0 |
| FR-DAST-002 | Engine SHALL support form-based, token-based (JWT/OAuth), cookie-based, and header-based authentication | P0 |
| FR-DAST-003 | Engine SHALL perform API security testing against OpenAPI/Swagger specifications | P0 |
| FR-DAST-004 | Engine SHALL enforce domain scope allowlists — never send requests outside approved targets | P0 |
| FR-DAST-005 | Engine SHALL support crawling depth limits and request rate limiting | P0 |
| FR-DAST-006 | Engine SHALL capture full HTTP request/response pairs as evidence for every finding | P0 |
| FR-DAST-007 | Engine SHALL detect OWASP Top 10 web vulnerability categories | P0 |
| FR-DAST-008 | Engine SHALL support GraphQL endpoint testing | P1 |
| FR-DAST-009 | Engine SHALL support WebSocket protocol testing | P2 |
| FR-DAST-010 | Engine SHALL support custom scan profiles (passive-only, active, aggressive) | P0 |
| FR-DAST-011 | Engine SHALL support session re-authentication when tokens expire during scan | P0 |

## 2.4 Authentication Session Broker

| ID | Requirement | Priority |
|---|---|---|
| FR-ASB-001 | Broker SHALL manage credentials for authenticated DAST scanning | P0 |
| FR-ASB-002 | Broker SHALL integrate with HashiCorp Vault, CyberArk, and generic secret stores | P0 |
| FR-ASB-003 | Broker SHALL support credential rotation during long-running scans | P0 |
| FR-ASB-004 | Broker SHALL never log or persist plaintext credentials | P0 |
| FR-ASB-005 | Broker SHALL support multi-step login sequences (MFA excluded — requires pre-authenticated tokens) | P0 |
| FR-ASB-006 | Broker SHALL provide session health monitoring and automatic re-authentication | P0 |

## 2.5 CI/CD Integration

| ID | Requirement | Priority |
|---|---|---|
| FR-CI-001 | Connector SHALL support Jenkins, GitLab CI, GitHub Actions, Azure DevOps | P0 |
| FR-CI-002 | Connector SHALL support generic webhook triggers | P0 |
| FR-CI-003 | Connector SHALL report scan results back to the pipeline as pass/fail gates | P0 |
| FR-CI-004 | Connector SHALL support policy-based gate criteria (severity thresholds, specific CWE blocking) | P0 |
| FR-CI-005 | Connector SHALL support scan result comments on pull/merge requests | P1 |
| FR-CI-006 | Connector SHALL accept source repository metadata (commit SHA, branch, author) | P0 |

## 2.6 Vulnerability Intelligence

| ID | Requirement | Priority |
|---|---|---|
| FR-VI-001 | Service SHALL ingest NVD, CVE, OSV, GitHub Advisory Database, CISA KEV | P0 |
| FR-VI-002 | Service SHALL normalize ingested data into a unified vulnerability schema | P0 |
| FR-VI-003 | Service SHALL support online pull and offline bundle ingestion | P0 |
| FR-VI-004 | Service SHALL correlate ingested CVEs with SCA-detected dependencies | P0 |
| FR-VI-005 | Service SHALL track exploit availability and active exploitation status (CISA KEV) | P0 |
| FR-VI-006 | Service SHALL trigger incremental rescans when new CVEs match existing project dependencies | P0 |
| FR-VI-007 | Service SHALL provide CVSS v3.1 and EPSS scoring where available | P0 |

## 2.7 Correlation Engine

| ID | Requirement | Priority |
|---|---|---|
| FR-CE-001 | Engine SHALL correlate SAST and DAST findings for the same vulnerability | P0 |
| FR-CE-002 | Engine SHALL deduplicate findings across scan runs | P0 |
| FR-CE-003 | Engine SHALL track finding lifecycle: new → confirmed → mitigated → resolved → reopened | P0 |
| FR-CE-004 | Engine SHALL assign composite risk scores combining CVSS, exploitability, and asset criticality | P0 |
| FR-CE-005 | Engine SHALL support manual finding triage (accept risk, false positive, defer) | P0 |

## 2.8 Policy Engine

| ID | Requirement | Priority |
|---|---|---|
| FR-PE-001 | Engine SHALL enforce scan policies (allowed targets, scan types, schedules) | P0 |
| FR-PE-002 | Engine SHALL enforce gate policies for CI/CD integration | P0 |
| FR-PE-003 | Engine SHALL support policy-as-code using OPA/Rego | P0 |
| FR-PE-004 | Engine SHALL support policy versioning and rollback | P0 |
| FR-PE-005 | Engine SHALL support team-scoped and organization-wide policies | P0 |

## 2.9 Evidence and Findings

| ID | Requirement | Priority |
|---|---|---|
| FR-EF-001 | System SHALL store full evidence for every finding (code snippets, HTTP traces, screenshots) | P0 |
| FR-EF-002 | System SHALL make findings immutable once persisted — amendments create new versions | P0 |
| FR-EF-003 | System SHALL support evidence export in standard formats (SARIF, JSON, CSV, PDF) | P0 |
| FR-EF-004 | System SHALL support finding annotations and comments by analysts | P0 |
| FR-EF-005 | System SHALL maintain full finding history with diff tracking | P0 |

## 2.10 Reporting

| ID | Requirement | Priority |
|---|---|---|
| FR-RP-001 | Service SHALL generate compliance-ready reports (executive summary, detailed technical) | P0 |
| FR-RP-002 | Service SHALL support scheduled report generation | P1 |
| FR-RP-003 | Service SHALL support report templates customizable per organization | P1 |
| FR-RP-004 | Service SHALL provide trend analysis across scan history | P1 |
| FR-RP-005 | Service SHALL export to PDF, HTML, JSON, SARIF, and CSV formats | P0 |

## 2.11 Rule and Update Management

| ID | Requirement | Priority |
|---|---|---|
| FR-UM-001 | System SHALL support signed rule update bundles | P0 |
| FR-UM-002 | System SHALL verify Ed25519 signatures on all update bundles before applying | P0 |
| FR-UM-003 | System SHALL support offline update ingestion via file upload | P0 |
| FR-UM-004 | System SHALL maintain rule version history with rollback capability | P0 |
| FR-UM-005 | System SHALL support custom rule overlays that survive updates | P0 |

## 2.12 Audit and Governance

| ID | Requirement | Priority |
|---|---|---|
| FR-AG-001 | System SHALL log every API call, configuration change, and scan action | P0 |
| FR-AG-002 | System SHALL produce append-only, tamper-evident audit logs | P0 |
| FR-AG-003 | System SHALL support audit log export to external SIEM systems | P0 |
| FR-AG-004 | System SHALL support data retention policies with configurable durations | P0 |
| FR-AG-005 | System SHALL provide audit log search and filtering | P0 |
