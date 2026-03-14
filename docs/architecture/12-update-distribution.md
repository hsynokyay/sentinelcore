# 12. Update Distribution Architecture

## 12.1 Update Categories

SentinelCore has three independent update streams, each with its own lifecycle:

| Category | Content | Frequency | Criticality |
|---|---|---|---|
| Platform Updates | Service binaries, container images, schema migrations | Monthly (scheduled) + hotfix | High — requires maintenance window |
| Rule Updates | SAST/DAST detection rules, scan patterns | Bi-weekly | Medium — no downtime required |
| Vulnerability Intelligence Updates | CVE data, advisory feeds, EPSS scores | Continuous (online) or weekly (offline) | Low — no downtime required |

## 12.2 Update Security Model

### 12.2.1 Signing Architecture

```
┌────────────────────────────────────────────────────────────┐
│              UPDATE BUILD PIPELINE (Vendor Side)           │
│                                                            │
│  Source Code / Rules / Feed Snapshots                      │
│         │                                                  │
│         ▼                                                  │
│  Build & Package                                           │
│         │                                                  │
│         ▼                                                  │
│  Integrity: SHA-256 manifest of all artifacts              │
│         │                                                  │
│         ▼                                                  │
│  Sign: Ed25519 signature over manifest                     │
│  (Private key in HSM — never exported)                     │
│         │                                                  │
│         ▼                                                  │
│  Publish: Signed bundle to distribution channel            │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│              UPDATE MANAGER (Customer Side)                 │
│                                                            │
│  Receive bundle (online pull or offline import)            │
│         │                                                  │
│         ▼                                                  │
│  Verify Ed25519 signature using pinned public key          │
│         │                                                  │
│         ▼                                                  │
│  Verify SHA-256 checksums of all artifacts in manifest     │
│         │                                                  │
│         ▼                                                  │
│  Validate compatibility (version constraints, schema)      │
│         │                                                  │
│         ▼                                                  │
│  Stage in quarantine (not applied yet)                     │
│         │                                                  │
│         ▼                                                  │
│  Admin approval required → Apply update                    │
└────────────────────────────────────────────────────────────┘
```

### 12.2.2 Key Management

| Key | Type | Storage | Rotation |
|---|---|---|---|
| Update signing key (private) | Ed25519 | Vendor HSM | Annual ceremony |
| Update verification key (public) | Ed25519 | Pinned in SentinelCore config | Updated with platform releases |
| Rule signing key (private) | Ed25519 | Vendor HSM (separate from platform key) | Annual ceremony |
| Rule verification key (public) | Ed25519 | Pinned in SentinelCore config | Updated with platform releases |

- Separate signing keys for platform updates vs. rule updates (blast radius isolation)
- Public keys can be rotated via a signed key rotation bundle (signed by the old key, containing the new key)
- Emergency key revocation: customer can pin a new public key manually

## 12.3 Platform Update Process

### 12.3.1 Online Update Flow

```
1. Update Manager checks for new versions (configurable interval)
   → GET https://updates.sentinelcore.example.com/api/v1/releases/latest
   → Response: version, changelog, bundle URL, signature URL

2. Download bundle and detached signature
   → Stored in MinIO staging bucket

3. Verify signature (Ed25519) and checksums (SHA-256)
   → Failure: alert operator, reject update

4. Compatibility check
   → Current version → target version upgrade path valid?
   → Schema migration compatibility verified

5. Stage update
   → Extract container images to local registry
   → Stage Helm chart values
   → Prepare database migration scripts

6. Operator approval
   → Dashboard notification: "Update v1.3.0 available and verified"
   → Operator reviews changelog and approves

7. Apply update (rolling deployment)
   → Database migrations applied
   → Services updated via Helm upgrade (rolling restart)
   → Health checks verified per service
   → Automatic rollback if health checks fail
```

### 12.3.2 Offline Update Flow

```
1. Vendor publishes update bundle to distribution portal
   → Customer security team downloads to approved media

2. Transfer bundle to air-gapped environment
   → Via approved data diode, encrypted USB, or secure file transfer

3. Import via Update Manager CLI or admin UI
   → sentinelcore-cli update import --bundle /path/to/bundle.tar.gz

4. Steps 3–7 from online flow apply identically
```

### 12.3.3 Rollback

- Every platform update creates a rollback snapshot:
  - Database snapshot (pg_dump of affected schemas)
  - Previous Helm release preserved (Helm rollback)
  - Previous container images tagged and retained
- Rollback command: `sentinelcore-cli update rollback --to-version 1.2.0`
- Rollback is automatic if post-update health checks fail within 10-minute window

## 12.4 Rule Update Process

Rule updates are lighter than platform updates and do not require service restarts:

```
1. Verify rule bundle signature (Ed25519, separate key from platform)
2. Verify checksums of all rule files
3. Validate rule syntax (parse all rules against rule schema)
4. Compare with existing rules:
   a. New rules → insert
   b. Modified vendor rules → update (preserving customer overrides)
   c. Deleted vendor rules → mark deprecated (not removed)
   d. Customer custom rules → NEVER modified
5. Update rule version metadata
6. Publish event to NATS: rules.updated
7. Workers reload rules on next scan (or on-demand via admin command)
```

### 12.4.1 Custom Rule Protection

```
Rule Resolution Order (highest priority first):
1. Customer custom rule with same rule_id → WINS
2. Vendor updated rule → applied if no custom override
3. Built-in rule → fallback

Customer custom rules are stored in a separate rule_set with source='custom'.
Vendor updates NEVER touch custom rule_sets.
```

## 12.5 Vulnerability Intelligence Update Process

See Section 11.7 for offline bundle format.

```
1. Verify bundle signature
2. Verify checksums per feed file
3. Import records through standard ingestion pipeline (Section 11.3)
4. Anomaly detection on imported data
5. Publish new vulnerability events for incremental rescan triggering
```

## 12.6 Update Bundle Format

### 12.6.1 Platform Update Bundle

```
sentinelcore-platform-1.3.0.tar.gz.sig     (Ed25519 detached signature)
sentinelcore-platform-1.3.0.tar.gz
  ├── manifest.json
  │   {
  │     "bundle_type": "platform",
  │     "version": "1.3.0",
  │     "min_upgrade_from": "1.1.0",
  │     "created_at": "2026-03-14T00:00:00Z",
  │     "artifacts": {
  │       "images": [
  │         {"name": "sentinelcore-controlplane", "tag": "1.3.0", "digest": "sha256:..."},
  │         {"name": "sentinelcore-orchestrator", "tag": "1.3.0", "digest": "sha256:..."},
  │         ...
  │       ],
  │       "helm_chart": {"checksum": "sha256:..."},
  │       "migrations": [
  │         {"version": "1.2.0_to_1.3.0", "checksum": "sha256:..."}
  │       ]
  │     },
  │     "changelog": "..."
  │   }
  ├── images/
  │   ├── sentinelcore-controlplane-1.3.0.tar  (OCI image archive)
  │   ├── sentinelcore-orchestrator-1.3.0.tar
  │   └── ...
  ├── helm/
  │   └── sentinelcore-1.3.0.tgz
  └── migrations/
      └── 1.2.0_to_1.3.0.sql
```

### 12.6.2 Rule Update Bundle

```
sentinelcore-rules-2026.03.01.tar.gz.sig
sentinelcore-rules-2026.03.01.tar.gz
  ├── manifest.json
  │   {
  │     "bundle_type": "rules",
  │     "version": "2026.03.01",
  │     "rule_count": 2500,
  │     "new_rules": 15,
  │     "modified_rules": 42,
  │     "deprecated_rules": 3,
  │     "artifacts": {
  │       "sast_rules": {"checksum": "sha256:..."},
  │       "dast_rules": {"checksum": "sha256:..."}
  │     }
  │   }
  ├── sast/
  │   └── rules.jsonl
  └── dast/
      └── rules.jsonl
```

## 12.7 Distribution Channels

| Channel | Audience | Method |
|---|---|---|
| Online repository | Connected deployments | HTTPS pull with API key authentication |
| Customer portal | Semi-connected / manual download | Web download with customer authentication |
| Secure media | Air-gapped deployments | Encrypted USB / approved transfer mechanism |
| Private registry | Enterprise customers with internal mirrors | OCI registry push (for container images) |

## 12.8 Update Compliance

| Requirement | Implementation |
|---|---|
| Audit trail | Every update action (download, verify, stage, approve, apply, rollback) is audit logged |
| Approval workflow | Platform updates require explicit admin approval |
| Signature verification | Mandatory — cannot be bypassed in production mode |
| Compatibility check | Mandatory — prevents applying incompatible updates |
| Rollback capability | Every update is rollback-capable within retention window |
| Change documentation | Changelog included in every bundle; rendered in admin dashboard |
