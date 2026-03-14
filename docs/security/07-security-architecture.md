# 7. Security Architecture

## 7.1 Security Design Principles

| Principle | Implementation |
|---|---|
| Zero Trust | All service-to-service calls use mTLS. No implicit trust. |
| Defense in Depth | Network policies + application auth + database RLS + audit logging |
| Least Privilege | Each service has a dedicated ServiceAccount with minimal RBAC |
| Secure by Default | All encryption enabled out of the box. No insecure fallbacks. |
| Fail Closed | Authorization failures deny access. Network policy defaults deny all. |
| Separation of Duties | Scan workers cannot access findings DB. Audit service has append-only access. |
| Immutability | Audit logs and evidence are write-once. Findings versions are append-only. |

## 7.2 Threat Model Summary

### 7.2.1 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│ UNTRUSTED                                                       │
│  • External CI/CD systems                                       │
│  • DAST scan targets (customer applications)                    │
│  • Vulnerability feed sources                                   │
│  • Source code repositories (may contain malicious code)         │
│  • User browsers / API clients                                  │
├─────────────────────────────────────────────────────────────────┤
│ SEMI-TRUSTED (isolated execution)                               │
│  • SAST workers (process untrusted code)                        │
│  • DAST workers (interact with external targets)                │
├─────────────────────────────────────────────────────────────────┤
│ TRUSTED (control plane)                                         │
│  • Control Plane, Orchestrator, Policy Engine                   │
│  • Correlation Engine, Reporting Service                        │
│  • Audit Log Service                                            │
├─────────────────────────────────────────────────────────────────┤
│ HIGHLY TRUSTED (data layer)                                     │
│  • PostgreSQL, MinIO, Vault                                     │
│  • Encryption keys, signing keys                                │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2.2 Key Threats and Mitigations

| Threat | Impact | Mitigation |
|---|---|---|
| Malicious code in scanned repository triggers RCE in SAST worker | Worker compromise | Sandboxed execution (seccomp, AppArmor), no network, ephemeral pods, resource limits |
| DAST worker used as SSRF proxy to scan internal infrastructure | Internal network exposure | Scope enforcement with domain allowlist, private IP range blocking, redirect chain validation |
| Credential leakage from Auth Session Broker | Target app compromise | Credentials never cached in memory beyond session; fetched from Vault per-request; audit logged |
| Tampered update bundle introduces malicious rules | Supply chain attack | Ed25519 signature verification, pinned public keys, update manifest with SHA-256 checksums |
| Audit log tampering to hide malicious activity | Loss of forensic evidence | Append-only access, HMAC chain integrity, periodic integrity verification job |
| Insider modifies policy to weaken scan scope enforcement | Unauthorized scan scope expansion | Policy changes require dual approval, all changes audit logged, system policies immutable |
| Database compromise exposes all findings | Data breach | Encryption at rest (AES-256-GCM), column-level encryption for sensitive fields, RLS enforcement |
| Vulnerability feed poisoning | False negatives/positives | Feed integrity verification, anomaly detection on feed updates, manual review for large changes |

## 7.3 Encryption

### 7.3.1 Encryption at Rest

| Component | Method | Key Management |
|---|---|---|
| PostgreSQL | TDE via LUKS on storage volume or pgcrypto column-level | Keys in Vault, auto-rotated quarterly |
| MinIO | Server-side encryption (SSE-S3) with AES-256-GCM | Master key in Vault, per-object keys derived |
| Redis | Encrypted RDB/AOF on encrypted volume | Volume encryption key in Vault |
| NATS JetStream | Encrypted file store on encrypted volume | Volume encryption key in Vault |
| Backup archives | AES-256-GCM encrypted before write | Backup encryption key in Vault (separate from data keys) |

### 7.3.2 Encryption in Transit

| Path | Protocol | Details |
|---|---|---|
| Client → API Gateway | TLS 1.3 | RSA-2048 or ECDSA-P256 certificates |
| Service ↔ Service | mTLS | Short-lived certificates from internal CA (cert-manager) |
| Service → PostgreSQL | TLS 1.3 | Client certificate authentication |
| Service → MinIO | TLS 1.3 | mTLS with ServiceAccount-bound certificates |
| Service → Vault | TLS 1.3 | mTLS with Kubernetes auth |
| Service → NATS | mTLS | Cluster-scoped client certificates |
| DAST Worker → Target | TLS (target-dependent) | Worker validates scope, not target certificates |

### 7.3.3 Key Management

```
┌──────────────────────────────────────────┐
│         HashiCorp Vault                  │
│                                          │
│  Secret Engines:                         │
│  ├── kv/          Credential storage     │
│  ├── transit/     Encryption as a svc    │
│  ├── pki/         Internal CA            │
│  └── database/    Dynamic DB credentials │
│                                          │
│  Auth Methods:                           │
│  ├── kubernetes/  Pod identity           │
│  └── approle/     Service identity       │
│                                          │
│  Unsealing: Shamir 3-of-5               │
│  Auto-unseal: AWS KMS / Azure KV         │
│  (for cloud-managed deployments)         │
└──────────────────────────────────────────┘
```

## 7.4 Authentication

### 7.4.1 User Authentication

SentinelCore supports multiple identity providers:

| Provider | Protocol | Details |
|---|---|---|
| OIDC | OpenID Connect | Keycloak, Okta, Azure AD, Google Workspace |
| LDAP | LDAP/LDAPS | Active Directory, OpenLDAP |
| SAML 2.0 | SAML | Enterprise SSO providers |
| Local | bcrypt-hashed passwords | Fallback for air-gapped environments without IdP |

**Session Management:**
- Sessions are JWT tokens signed with RS256 (key pair in Vault)
- Access token TTL: 15 minutes (configurable)
- Refresh token TTL: 8 hours (configurable)
- Token refresh is transparent to API clients
- All sessions tracked in Redis for revocation support
- Force-logout revokes all active sessions for a user

### 7.4.2 Service-to-Service Authentication

- **Kubernetes ServiceAccount tokens** bound to specific pods
- **mTLS certificates** issued by internal cert-manager CA
- Certificate rotation: every 24 hours (automatic)
- No static API keys between services

### 7.4.3 CI/CD Authentication

- **API tokens** with scoped permissions (scan-only, read-only)
- Token creation requires admin approval
- Tokens have mandatory expiration (max 1 year)
- Each token bound to a specific project scope
- Token usage audit logged

## 7.5 Network Security

### 7.5.1 Kubernetes Network Policies

Every namespace has a **default-deny** ingress and egress policy. Allowed traffic is explicitly declared:

```yaml
# Example: DAST worker default policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: dast-worker-default
  namespace: sentinelcore-dast
spec:
  podSelector:
    matchLabels:
      app: sentinelcore-dast-worker
  policyTypes:
    - Ingress
    - Egress
  ingress: []  # No inbound traffic
  egress:
    # Allow DNS resolution
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
    # Allow NATS communication
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: sentinelcore-data
          podSelector:
            matchLabels:
              app: nats
      ports:
        - protocol: TCP
          port: 4222
    # Scan target access controlled by dynamic NetworkPolicy per scan
```

### 7.5.2 Dynamic DAST Scope Enforcement

When a DAST scan is dispatched, the Orchestrator creates a **temporary, scan-specific NetworkPolicy** that permits egress only to the approved scan targets:

```yaml
# Generated per-scan by Orchestrator
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: dast-scan-{scan_id}
  namespace: sentinelcore-dast
  labels:
    scan-id: "{scan_id}"
  annotations:
    sentinelcore.io/expires: "2026-03-14T12:00:00Z"
spec:
  podSelector:
    matchLabels:
      scan-id: "{scan_id}"
  egress:
    - to:
        - ipBlock:
            cidr: 10.1.2.3/32  # resolved target IP
      ports:
        - protocol: TCP
          port: 443
```

This NetworkPolicy is deleted automatically when the scan completes.

## 7.6 SAST Worker Sandboxing

SAST workers process untrusted code and must be hardened:

| Control | Implementation |
|---|---|
| Filesystem | Read-only root filesystem; writable tmpfs for analysis only |
| Network | No network egress (all rules pre-loaded) |
| Capabilities | `drop: ALL`, no privileged escalation |
| Seccomp | Custom profile allowing only required syscalls |
| AppArmor | Restricted profile preventing file access outside work directory |
| Resources | CPU and memory limits enforced; OOM kill on exceeded |
| Timeout | Wall-clock timeout enforced by Orchestrator (kills pod on expiry) |
| User | Non-root user (UID 65534) |
| Volume | Ephemeral — destroyed on pod termination |

## 7.7 Secret Management

### 7.7.1 Secret Categories

| Category | Storage | Access Pattern |
|---|---|---|
| Scan credentials | Vault KV | Fetched by Auth Session Broker at scan time |
| Database passwords | Vault Dynamic Secrets | Rotated automatically, leased per service |
| TLS certificates | cert-manager / Vault PKI | Auto-rotated every 24h |
| API signing keys | Vault Transit | Never exported; sign/verify operations via API |
| Update signing keys | Offline HSM or Vault | Used only by update build pipeline |
| Backup encryption keys | Vault KV (separate mount) | Accessed only by backup operator role |

### 7.7.2 Secret Zero Problem

The initial Vault unseal secret (secret zero) is handled via:

1. **Shamir's Secret Sharing** — 3-of-5 key shares distributed to designated key holders
2. **Auto-unseal (optional)** — Vault auto-unseals using a cloud KMS key (AWS KMS, Azure Key Vault, GCP KMS) for cloud-managed deployments
3. **Air-gapped environments** — Shamir shares stored on separate encrypted USB drives, held by different individuals

## 7.8 Supply Chain Security

| Control | Implementation |
|---|---|
| Container images | Signed with cosign; verified at deployment by admission controller |
| Base images | Distroless or Alpine-minimal; rebuilt monthly with latest patches |
| Dependencies | Dependency lock files; SCA scan of SentinelCore's own dependencies |
| Build pipeline | Reproducible builds; SBOM generated for every release |
| Update bundles | Ed25519 signed; public key pinned in platform configuration |
| Rule updates | Signed independently from platform updates |
| Vulnerability feeds | Verified against source checksums; anomaly detection on large deltas |

## 7.9 Incident Response Integration

SentinelCore provides hooks for customer incident response:

- **Webhook notifications** for critical findings or scan failures
- **SIEM export** of audit logs (syslog, HTTPS, Kafka)
- **Alert rules** configurable via the Policy Engine
- **Forensic export** — full evidence chain for any finding, packaged for external analysis
