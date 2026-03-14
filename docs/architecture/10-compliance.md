# 10. Compliance Considerations

## 10.1 Compliance Framework Alignment

SentinelCore's architecture supports evidence collection and control implementation for the following compliance frameworks:

| Framework | Relevance | Key Controls Supported |
|---|---|---|
| SOC 2 Type II | Primary | CC6 (Logical Access), CC7 (System Operations), CC8 (Change Management) |
| ISO 27001 | Primary | A.8 (Asset Management), A.9 (Access Control), A.12 (Operations Security), A.14 (System Acquisition) |
| PCI DSS v4.0 | Secondary | Req 6 (Secure Software), Req 10 (Logging & Monitoring), Req 11 (Security Testing) |
| FedRAMP | Secondary | AC (Access Control), AU (Audit), CM (Configuration Management), SI (System Integrity) |
| NIST 800-53 | Reference | AC, AU, CM, IA, SC, SI control families |
| GDPR | Reference | Article 25 (Data Protection by Design), Article 32 (Security of Processing) |

## 10.2 Control Mapping

### 10.2.1 Access Control (SOC 2 CC6 / ISO 27001 A.9 / NIST AC)

| Control | SentinelCore Implementation | Evidence |
|---|---|---|
| Role-based access | RBAC with OPA enforcement (Section 9) | Role assignments, policy definitions |
| Least privilege | Scoped API keys, team isolation, service accounts | Permission matrix, key configurations |
| Authentication | OIDC/LDAP/SAML with MFA support | Login audit logs, IdP integration config |
| Session management | JWT with short TTL, Redis-backed revocation | Token policies, session logs |
| Access review | Audit log of all access events with search | Audit log exports, access reports |

### 10.2.2 Audit and Accountability (SOC 2 CC7 / ISO 27001 A.12 / NIST AU)

| Control | SentinelCore Implementation | Evidence |
|---|---|---|
| Comprehensive logging | All state-changing operations logged (Section 8) | Audit log entries |
| Log integrity | HMAC chain, append-only storage | Integrity verification reports |
| Log retention | Configurable retention with minimum 1 year | Retention policy configuration |
| Log review | Searchable audit logs, Grafana dashboards | Access logs to audit system |
| Tamper detection | Hourly integrity verification job | Integrity check reports, alert history |

### 10.2.3 Change Management (SOC 2 CC8 / ISO 27001 A.14 / NIST CM)

| Control | SentinelCore Implementation | Evidence |
|---|---|---|
| Update verification | Ed25519 signatures on all update bundles | Update application audit logs |
| Configuration tracking | All config changes audit logged with before/after diff | Configuration change audit trail |
| Rule versioning | Semantic versioning with rollback support | Rule version history |
| Policy versioning | Version-tracked OPA policies | Policy version history |
| Approval workflows | Multi-party approval for critical changes | Approval audit trail |

### 10.2.4 Data Protection (GDPR Art. 25 / ISO 27001 A.8)

| Control | SentinelCore Implementation | Evidence |
|---|---|---|
| Encryption at rest | AES-256-GCM for all stored data | Encryption configuration, key management logs |
| Encryption in transit | mTLS for all internal communication | Certificate inventory, TLS configuration |
| Data isolation | Team-scoped RLS, network segmentation | Database policies, NetworkPolicy resources |
| Data retention | Configurable retention with automated enforcement | Retention policy, deletion logs |
| Data minimization | Only security-relevant data collected and stored | Data model documentation |

### 10.2.5 Vulnerability Management (PCI DSS Req 6 & 11 / NIST SI)

| Control | SentinelCore Implementation | Evidence |
|---|---|---|
| Regular scanning | Scheduled SAST/DAST scans | Scan history, schedule configuration |
| Vulnerability tracking | Finding lifecycle management with SLA tracking | Finding status reports |
| Remediation tracking | Finding state transitions with timestamps | Remediation timeline reports |
| Risk acceptance | Documented risk acceptance with approval workflow | Risk acceptance records |
| Known vulnerability monitoring | CISA KEV integration, continuous CVE monitoring | Vulnerability intelligence feed logs |

## 10.3 Compliance Reporting

SentinelCore generates the following compliance-ready reports:

### 10.3.1 Standard Reports

| Report | Content | Format |
|---|---|---|
| Security Posture Summary | Overall risk score, finding counts by severity, trend | PDF, HTML |
| Vulnerability Remediation Report | Open findings, remediation SLA status, overdue items | PDF, CSV |
| Scan Coverage Report | Projects scanned, scan frequency, coverage gaps | PDF, HTML |
| Access Review Report | User roles, access events, privilege usage | PDF, CSV |
| Audit Trail Report | Filtered audit events for specified time range | JSONL, CSV, PDF |
| Configuration Baseline | Current platform configuration with change history | JSON, PDF |
| Update Compliance Report | Update history, current versions, patch status | PDF |

### 10.3.2 Framework-Specific Reports

| Report | Framework | Content |
|---|---|---|
| SOC 2 Evidence Package | SOC 2 | Control evidence organized by Trust Service Criteria |
| ISO 27001 Control Report | ISO 27001 | Evidence mapped to Annex A controls |
| PCI ASV Report | PCI DSS | Vulnerability scan results in ASV-compatible format |
| NIST Control Assessment | NIST 800-53 | Control implementation status by family |

## 10.4 Evidence Chain of Custody

### 10.4.1 Evidence Integrity

Every finding evidence artifact is:

1. **Hashed** — SHA-256 hash computed at creation time
2. **Stored immutably** — MinIO with object versioning and optional WORM lock
3. **Referenced** — Hash stored in findings database alongside evidence path
4. **Verifiable** — Integrity verification available on demand
5. **Timestamped** — Creation timestamp in both metadata and audit log

### 10.4.2 Evidence Lifecycle

```
Evidence Created (scan time)
  ├── SHA-256 hash computed
  ├── Uploaded to MinIO (versioned, encrypted)
  ├── Hash recorded in findings.findings.evidence_ref
  └── Audit event: evidence.created

Evidence Accessed (analyst/report)
  └── Audit event: evidence.accessed

Evidence Exported (compliance report)
  ├── Integrity verified (hash check)
  ├── Included in report with hash
  └── Audit event: evidence.exported

Evidence Retained/Expired
  ├── Retention policy evaluated
  ├── If expired: moved to archive tier
  └── Audit event: evidence.archived / evidence.deleted
```

## 10.5 Data Residency and Sovereignty

SentinelCore is designed for complete data sovereignty:

- **No external data transmission** — All data stays within the deployment boundary
- **No telemetry** — No usage data, error reports, or analytics sent externally
- **No phone-home** — No license validation calls, no update checks (in air-gapped mode)
- **Configurable data location** — All storage components use customer-provided infrastructure
- **Export controls** — Data export requires explicit authorization and is audit logged

## 10.6 Compliance Automation

### 10.6.1 Automated Evidence Collection

A scheduled job runs daily to:
1. Verify all required scans were executed per policy
2. Check finding remediation SLA compliance
3. Verify audit log integrity
4. Validate certificate expiration status
5. Check backup completion and integrity
6. Generate compliance status dashboard data

### 10.6.2 Compliance Alerts

| Alert | Trigger |
|---|---|
| Scan SLA breach | Required scan not executed within policy window |
| Remediation SLA breach | Critical/high finding open beyond SLA deadline |
| Audit integrity failure | HMAC chain broken or entries missing |
| Certificate expiry warning | Certificate expires within 30 days |
| Backup failure | Daily backup did not complete successfully |
| Policy violation | Scan executed outside approved scope |
