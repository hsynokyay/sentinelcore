# 14. Air-Gapped Deployment Model

## 14.1 Overview

Air-gapped deployment is a first-class operating mode, not an afterthought. SentinelCore is designed so that every feature works without network connectivity. Online mode is an optimization for convenience, not a dependency.

## 14.2 Air-Gap Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 CONNECTED ENVIRONMENT                            │
│                 (Vendor / Staging)                               │
│                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐        │
│  │  Update      │   │  Vuln Intel  │   │  Rule        │        │
│  │  Build       │   │  Bundle      │   │  Bundle      │        │
│  │  Pipeline    │   │  Generator   │   │  Generator   │        │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘        │
│         │                  │                   │                 │
│         ▼                  ▼                   ▼                 │
│  ┌──────────────────────────────────────────────────────┐       │
│  │            Signed Bundle Repository                   │       │
│  │  platform-1.3.0.tar.gz.sig                           │       │
│  │  rules-2026.03.01.tar.gz.sig                         │       │
│  │  vuln-intel-2026.03.14.tar.gz.sig                    │       │
│  └──────────────────────────┬───────────────────────────┘       │
└─────────────────────────────┼───────────────────────────────────┘
                              │
                    ┌─────────┼─────────┐
                    │   DATA DIODE /    │
                    │   APPROVED MEDIA  │
                    │   TRANSFER        │
                    └─────────┼─────────┘
                              │
┌─────────────────────────────┼───────────────────────────────────┐
│                 AIR-GAPPED ENVIRONMENT                           │
│                 (Customer Production)                            │
│                                                                  │
│  ┌──────────────────────────▼───────────────────────────┐       │
│  │              Transfer Station                         │       │
│  │  (Hardened bastion with bundle validation)            │       │
│  │                                                       │       │
│  │  1. Receive media                                     │       │
│  │  2. Malware scan (ClamAV or equivalent)               │       │
│  │  3. Signature verification (Ed25519)                  │       │
│  │  4. Transfer to internal staging                      │       │
│  └──────────────────────────┬───────────────────────────┘       │
│                             │                                    │
│  ┌──────────────────────────▼───────────────────────────┐       │
│  │              Internal Bundle Registry                 │       │
│  │  (MinIO or NFS share within air-gapped network)       │       │
│  └──────────────────────────┬───────────────────────────┘       │
│                             │                                    │
│  ┌──────────────────────────▼───────────────────────────┐       │
│  │              SentinelCore Cluster                     │       │
│  │                                                       │       │
│  │  Update Manager ◄── imports from internal registry    │       │
│  │  Vuln Intel    ◄── imports vuln bundles               │       │
│  │  Rule Repo     ◄── imports rule bundles               │       │
│  │                                                       │       │
│  │  Container Registry (Harbor / local registry)         │       │
│  │  ◄── loaded with OCI images from platform bundle      │       │
│  └───────────────────────────────────────────────────────┘       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## 14.3 Air-Gapped Configuration Differences

| Component | Connected Mode | Air-Gapped Mode |
|---|---|---|
| Vuln Intel feeds | HTTP pull from NVD, OSV, etc. | Offline bundle import |
| Rule updates | HTTP pull from vendor repository | Offline bundle import |
| Platform updates | HTTP pull from vendor | Offline bundle import |
| Container registry | Pull from vendor registry | Local Harbor / registry with pre-loaded images |
| Identity provider | OIDC/LDAP (may be internal) | LDAP / local accounts |
| NTP | External NTP servers | Internal NTP (critical for cert validation and audit timestamps) |
| Vault auto-unseal | Cloud KMS | Shamir's Secret Sharing (manual ceremony) |
| Certificate authority | External CA or Let's Encrypt | Internal CA (cert-manager with self-signed root) |
| SIEM export | HTTPS webhook | File export or syslog to local SIEM |

## 14.4 Air-Gap Specific Requirements

### 14.4.1 Internal Container Registry

Air-gapped deployments require a local container registry pre-populated with SentinelCore images:

```bash
# On connected workstation: export images from bundle
sentinelcore-cli bundle extract-images \
  --bundle sentinelcore-platform-1.3.0.tar.gz \
  --output ./images/

# On air-gapped network: load into local registry
sentinelcore-cli registry load \
  --source ./images/ \
  --registry harbor.internal.example.com/sentinelcore
```

### 14.4.2 Internal Time Source

Accurate time is critical for:
- TLS certificate validation
- Audit log timestamps
- Scan scheduling
- Token expiration

Air-gapped environments MUST have an internal NTP server. SentinelCore validates time sync at startup and alerts on clock drift > 5 seconds.

### 14.4.3 Internal DNS

All service discovery uses Kubernetes internal DNS. No external DNS resolution required.

### 14.4.4 Internal CA

cert-manager is configured with a self-signed root CA for mTLS certificates:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: sentinelcore-ca
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: sentinelcore-root-ca
spec:
  isCA: true
  commonName: sentinelcore-root-ca
  secretName: sentinelcore-root-ca-secret
  issuerRef:
    name: sentinelcore-ca
    kind: ClusterIssuer
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: sentinelcore-internal
spec:
  ca:
    secretName: sentinelcore-root-ca-secret
```

## 14.5 Bundle Transfer Procedures

### 14.5.1 Transfer Checklist

```
□ Bundle downloaded from vendor portal by authorized personnel
□ Bundle signature verified on connected workstation
□ Bundle transferred to approved media (encrypted USB / data diode)
□ Chain of custody form signed
□ Media scanned for malware at transfer station
□ Bundle signature re-verified on air-gapped transfer station
□ Bundle uploaded to internal staging registry
□ Import initiated via Update Manager
□ Update Manager verifies signature (third verification)
□ Admin reviews and approves application
□ Audit log confirms successful import
```

### 14.5.2 Bundle Transfer CLI

```bash
# Verify bundle on connected workstation
sentinelcore-cli bundle verify \
  --bundle sentinelcore-platform-1.3.0.tar.gz \
  --signature sentinelcore-platform-1.3.0.tar.gz.sig \
  --public-key /path/to/sentinelcore-update-key.pub

# Output:
# ✓ Signature valid (Ed25519)
# ✓ Manifest checksums verified (15/15 artifacts)
# ✓ Compatible with installed version 1.2.0
# ✓ Bundle is safe to transfer

# Import on air-gapped system
sentinelcore-cli update import \
  --bundle /mnt/transfer/sentinelcore-platform-1.3.0.tar.gz \
  --signature /mnt/transfer/sentinelcore-platform-1.3.0.tar.gz.sig

# Import vuln intel
sentinelcore-cli vuln-intel import \
  --bundle /mnt/transfer/vuln-intel-2026-03-14.tar.gz \
  --signature /mnt/transfer/vuln-intel-2026-03-14.tar.gz.sig
```

## 14.6 Air-Gap Operational Considerations

### 14.6.1 Vulnerability Intelligence Freshness

In air-gapped deployments, vulnerability intelligence is only as fresh as the last imported bundle. Recommendations:

| Environment Risk Level | Recommended Import Frequency |
|---|---|
| Critical infrastructure | Weekly |
| High security | Bi-weekly |
| Standard | Monthly |

The platform displays a "Vulnerability Intelligence Freshness" indicator showing days since last update, with configurable warning thresholds.

### 14.6.2 License Management

- Licenses are node-locked or hardware-fingerprinted
- License files are signed and imported offline
- License expiration alerts start 60 days before expiry
- Grace period: 30 days after expiration (full functionality, persistent warning)

### 14.6.3 Support and Diagnostics

For air-gapped environments, support diagnostics are collected as encrypted export bundles:

```bash
# Generate diagnostic bundle (no sensitive data)
sentinelcore-cli support diagnostics \
  --output /mnt/transfer/diagnostics-2026-03-14.tar.gz \
  --encrypt-to /path/to/vendor-support-key.pub

# Bundle contains:
# - Service health status
# - Configuration (secrets redacted)
# - Error logs (last 7 days)
# - Metrics summary
# - Version inventory
# Does NOT contain: findings, evidence, audit logs, credentials
```

## 14.7 Semi-Connected Mode

For environments that have limited, controlled outbound connectivity:

```yaml
# values-semiconnected.yaml
connectivity:
  mode: semi-connected
  allowedOutbound:
    # Vulnerability feeds only
    - host: services.nvd.nist.gov
      port: 443
    - host: api.osv.dev
      port: 443
    - host: api.github.com
      port: 443
    - host: www.cisa.gov
      port: 443
    - host: epss.cyentia.com
      port: 443
  proxy:
    httpProxy: "http://proxy.internal:3128"
    httpsProxy: "http://proxy.internal:3128"
    noProxy: "10.0.0.0/8,.internal.example.com"
  # Platform and rule updates still via offline bundles
  updates:
    mode: offline
```
