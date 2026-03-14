# SentinelCore Secure Update Trust Architecture

**Status:** Design
**Date:** 2026-03-14
**Model:** Option A — HSM-backed root key hierarchy
**Supersedes:** Section 12.2 of the original architecture (key management)

### Documents to Update on Adoption

| Document | Sections | Changes needed |
|---|---|---|
| `architecture/12-update-distribution.md` | 12.2.2 (Key Management) | Replace flat key model with root→signing hierarchy; remove "signed by old key" rotation |
| `architecture/12-update-distribution.md` | 12.6.1, 12.6.2 (Bundle Format) | Update bundle layout to include signing_key_cert, revocations; update manifest to format_version 2 |
| `security/07-security-architecture.md` | 7.7.1 (Secret Categories) | Remove "or Vault" for update signing keys; HSM-only is now mandatory for all signing keys |
| `security/07-security-architecture.md` | 7.8 (Supply Chain Security) | Add root key hierarchy, revocation mechanism, and certificate chain to supply chain controls |

---

## 1. Problem Statement

SentinelCore delivers security-critical updates (rules, vulnerability intelligence, scanner engines) to on-premises and air-gapped deployments. A compromised update could inject malicious detection rules that hide real vulnerabilities, introduce false positives to create alert fatigue, or execute arbitrary code via scanner engine updates.

The original architecture (Section 12.2.2) used a single Ed25519 signing key with self-signed key rotation — a compromised key could sign a rotation bundle pointing to an attacker-controlled key, permanently hijacking the update chain. This design eliminates that circular dependency.

### Threat Model for Updates

| Threat | Impact | This design's mitigation |
|---|---|---|
| Signing key compromised | Attacker signs malicious bundles | Signing key != root key; rotate via root without customer disruption |
| Root key compromised | Attacker can issue new signing key certificates | Manual customer pin override (out-of-band); most severe but least likely |
| Build pipeline compromised | Legitimate key signs malicious content | Out of scope for key management; mitigated by SBOM, reproducible builds, review gates |
| Replay attack (old bundle re-presented) | Customer downgrades to vulnerable version | Version monotonicity enforcement; reject bundles older than installed version |
| Bundle tampered in transit | Modified artifacts delivered to customer | SHA-256 manifest integrity; signature covers manifest |
| DNS/TLS interception of update channel | MITM serves attacker-controlled bundles | Ed25519 signature verification independent of transport; TLS is defense-in-depth only |
| Rogue insider at vendor signs unauthorized update | Malicious update reaches customers | Signing key access requires quorum (2-of-3 ceremony participants); HSM audit log |

---

## 2. Key Hierarchy

```
                    ┌─────────────────────────┐
                    │     ROOT KEY PAIR        │
                    │     Ed25519              │
                    │     HSM-only, offline    │
                    │     Never signs content  │
                    └────────────┬────────────┘
                                 │
                    Signs:       │
                    - Signing key certificates
                    - Revocation notices
                    - Root rotation advisories (emergency only)
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                   │
   ┌──────────▼────────┐ ┌──────▼──────────┐ ┌─────▼───────────┐
   │ PLATFORM SIGNING  │ │ RULE SIGNING    │ │ VULN INTEL      │
   │ KEY               │ │ KEY             │ │ SIGNING KEY     │
   │ Ed25519           │ │ Ed25519         │ │ Ed25519         │
   │ 1-year validity   │ │ 1-year validity │ │ 1-year validity │
   │ Signs: platform   │ │ Signs: SAST +   │ │ Signs: CVE/     │
   │ update bundles    │ │ DAST rule packs │ │ advisory bundles│
   └───────────────────┘ └─────────────────┘ └─────────────────┘
```

### 2.1 Key Properties

| Key | Algorithm | Storage | Lifetime | Purpose | Who holds it |
|---|---|---|---|---|---|
| Root private key | Ed25519 | Primary HSM + backup HSM (geographically separated) | Indefinite (rotate only on compromise) | Sign signing key certificates, revocations | Vendor security team (ceremony-gated) |
| Root public key | Ed25519 | Pinned in SentinelCore installation media + customer config | Matches root private | Verify signing key certificates | Every SentinelCore deployment |
| Platform signing key | Ed25519 | Vendor HSM (online partition) | 1 year | Sign platform update bundles | Vendor build pipeline (ceremony-provisioned) |
| Rule signing key | Ed25519 | Vendor HSM (online partition) | 1 year | Sign SAST/DAST rule packs | Vendor rule engineering team |
| Vuln intel signing key | Ed25519 | Vendor HSM (online partition) | 1 year | Sign vulnerability intelligence bundles | Vendor intel pipeline |

**Note on Vault:** The original security architecture (Section 7.7.1) lists "Offline HSM or Vault" for update signing key storage. This design supersedes that — **HSM-only storage is mandatory for all signing keys** (root and signing). Vault transit is not acceptable because Vault auto-unseal via cloud KMS reduces the key storage to a software-accessible key, which does not provide the physical access barrier required for supply chain trust. If a deployment cannot provision an HSM, it must use a cloud HSM service (AWS CloudHSM, Azure Dedicated HSM, GCP Cloud HSM) — not Vault transit.

### 2.2 Blast Radius Isolation

Three separate signing keys ensure:
- **Rule signing key compromised:** attacker can push malicious rules but cannot push malicious binaries or tainted vuln intel
- **Platform signing key compromised:** attacker can push malicious binaries but cannot alter detection rules in isolation
- **Vuln intel signing key compromised:** attacker can poison vulnerability data but cannot execute code or alter scan behavior

No single signing key compromise gives full control. Root key compromise is required to take over the entire update chain.

### 2.3 Why Not X.509 / PKI

Ed25519 with a custom certificate format is chosen over X.509 because:
1. SentinelCore operates in air-gapped environments where OCSP/CRL infrastructure is unavailable
2. The trust hierarchy is simple (depth=2, single root) — X.509 chain validation is unnecessary complexity
3. Ed25519 signatures are 64 bytes vs. RSA-2048 at 256 bytes — smaller bundles for constrained transfer media
4. No dependency on OpenSSL or ASN.1 parsing libraries in the verification path (reduced attack surface)
5. Custom format is auditable: a signing key certificate is a JSON document a human can read and verify

---

## 3. Signing Key Certificate Format

A **signing key certificate** is a JSON document signed by the root key that authorizes a specific public key to sign bundles of a specific type for a specific time window.

### 3.1 Schema

```json
{
  "format": "sentinelcore-signing-key-certificate",
  "format_version": 1,
  "serial": "SKC-2026-PLAT-001",
  "purpose": "platform_signing",
  "public_key": "<base64-encoded-ed25519-public-key-32-bytes>",
  "valid_from": "2026-01-15T00:00:00Z",
  "valid_until": "2027-01-15T00:00:00Z",
  "issued_at": "2026-01-10T14:30:00Z",
  "issued_by_root_fingerprint": "sha256:<hex-encoded-sha256-of-root-public-key>",
  "replaces_serial": "SKC-2025-PLAT-001",
  "metadata": {
    "ceremony_id": "CEREMONY-2026-01",
    "participants": ["role:security-lead", "role:engineering-lead", "role:compliance-officer"]
  }
}
```

**Detached signature file** (accompanies the certificate):
```
<base64-encoded-ed25519-signature-over-canonical-json-of-certificate>
```

### 3.2 Field Definitions

| Field | Required | Description |
|---|---|---|
| `format` | yes | Constant: `sentinelcore-signing-key-certificate` |
| `format_version` | yes | Schema version. Currently `1`. |
| `serial` | yes | Unique, monotonically increasing identifier. Format: `SKC-{year}-{purpose_code}-{seq}`. |
| `purpose` | yes | One of: `platform_signing`, `rule_signing`, `vuln_intel_signing`. Certificate is valid ONLY for this purpose. |
| `public_key` | yes | Base64-encoded Ed25519 public key (32 bytes raw). |
| `valid_from` | yes | ISO 8601 UTC. Certificate is not valid before this time. |
| `valid_until` | yes | ISO 8601 UTC. Certificate is not valid after this time. |
| `issued_at` | yes | ISO 8601 UTC. When the root key signed this certificate. |
| `issued_by_root_fingerprint` | yes | SHA-256 of the root public key that signed this certificate. Customer verifies this matches their pinned root. |
| `replaces_serial` | no | Serial of the signing key certificate this one replaces. Advisory only — enables customers to track key lineage but is not cryptographically verified (the root signature on the certificate is the trust anchor, not the lineage chain). |
| `metadata` | no | Ceremony audit information. Included in the signed content — provides tamper-evident ceremony audit trail. |

### 3.3 Canonical JSON Serialization

All signed JSON documents (certificates, manifests, revocation lists) use the same canonical form. This eliminates the class of bugs where different documents use different serialization rules.

**Canonicalization procedure:**

1. Sort all keys lexicographically at every nesting level
2. Serialize with no whitespace (`json.Marshal` in Go, `json.dumps(separators=(',',':'), sort_keys=True)` in Python)
3. UTF-8 encode the result
4. The resulting bytes are the input to Ed25519 Sign/Verify

Ed25519 internally hashes its input with SHA-512 before signing. Do NOT pre-hash the canonical bytes with SHA-256 or any other hash — sign the canonical bytes directly. Pre-hashing adds an unnecessary assumption (hash second-preimage resistance) and gains nothing.

**Important:** All fields are signed, including `metadata`. This ensures the ceremony audit trail embedded in certificates is tamper-evident. There is no selective field exclusion.

### 3.4 Verification Algorithm

```
VERIFY_SIGNING_KEY_CERTIFICATE(cert_json, cert_sig, pinned_root_pubkey):
  1. Parse cert_json as JSON
  2. Assert cert.format == "sentinelcore-signing-key-certificate"
  3. Assert cert.format_version == 1  (or ≤ max supported version)
  4. Assert cert.issued_by_root_fingerprint == sha256(pinned_root_pubkey)
  5. Compute canonical_bytes = canonicalize(cert_json)   [Section 3.3]
  6. Assert ed25519_verify(pinned_root_pubkey, canonical_bytes, cert_sig) == true
     (sign/verify over canonical bytes directly — no pre-hashing)
  7. Assert cert.serial NOT IN local_revocation_list
  8. Assert cert.valid_from ≤ now()  (with 48-hour grace for air-gapped clock drift)
  9. Assert cert.valid_until ≥ now() (with 48-hour grace for air-gapped clock drift)
  10. Return cert.public_key, cert.purpose
```

The 48-hour grace window on time validation accommodates air-gapped environments where NTP may drift. This is an accepted trade-off — the window is short enough that a revoked certificate cannot be meaningfully exploited within it, especially given that air-gapped transfers take hours to days.

---

## 4. Revocation

Since SentinelCore operates in environments without network access to revocation infrastructure (OCSP, CRL), revocation uses a **signed revocation list** distributed with every bundle.

### 4.1 Revocation List Format

```json
{
  "format": "sentinelcore-revocation-list",
  "format_version": 1,
  "issued_at": "2026-03-14T00:00:00Z",
  "sequence": 47,
  "revoked_certificates": [
    {
      "serial": "SKC-2025-RULE-002",
      "revoked_at": "2026-02-01T00:00:00Z",
      "reason": "key_compromise"
    }
  ],
  "revoked_root_keys": []
}
```

**Signature:** Signed by root key (same canonical JSON + Ed25519 process as certificates).

### 4.2 Revocation Distribution

| Channel | Mechanism |
|---|---|
| Platform update bundle | `revocations.json` + `revocations.json.sig` included in every bundle |
| Rule update bundle | Same — revocation list always included |
| Vuln intel bundle | Same |
| Standalone revocation bundle | For emergency distribution when no regular update is imminent |
| Air-gapped | Revocation bundle transferred via same media path as updates |

### 4.3 Revocation Processing

```
ON_RECEIVE_REVOCATION_LIST(revocation_json, revocation_sig, pinned_root_pubkey):
  1. Verify signature against pinned_root_pubkey
  2. Assert revocation.sequence > local_stored_sequence  (monotonic — prevents replay of old list)
  3. Store revocation list locally (persistent storage)
  4. For each revoked serial:
     - If serial matches any locally cached signing key certificate → invalidate it
     - Log audit event: "signing_key_revoked"
  5. If revoked_root_keys is non-empty:
     - Log CRITICAL alert: root key compromised
     - Enter update-lockdown mode (see Section 8.3)
```

### 4.4 Local Revocation Storage

The Update Manager maintains a persistent local revocation list at:
```
/var/lib/sentinelcore/trust/revocations.json
/var/lib/sentinelcore/trust/revocations.json.sig
```

This file is loaded on every bundle verification. It is updated whenever a newer revocation list arrives (higher sequence number). The file is integrity-protected by its root key signature — tampering is detected on next load.

---

## 5. Bundle Signing Flow (Vendor Side)

### 5.1 Signing Pipeline

```
┌────────────────────────────────────────────────────────────────────┐
│                    VENDOR BUILD PIPELINE                            │
│                                                                    │
│  1. Build artifacts (binaries, rules, or vuln intel data)          │
│  2. Compute SHA-256 of every artifact → manifest.json              │
│  3. Include current signing key certificate in bundle:             │
│     signing_key_cert.json + signing_key_cert.json.sig              │
│  4. Include current revocation list in bundle:                     │
│     revocations.json + revocations.json.sig                        │
│  5. Canonicalize manifest.json (Section 3.3: sort keys,            │
│     no whitespace, UTF-8 encode)                                   │
│  6. Sign canonical manifest bytes with the appropriate signing key:│
│     manifest.json.sig = Ed25519_Sign(signing_private_key,          │
│                                       canonical_bytes(manifest))   │
│     (sign canonical bytes directly — no pre-hashing)               │
│  7. Package: tar.gz containing all artifacts + manifest +          │
│     signatures + signing key certificate + revocation list         │
│  8. Publish to distribution channel                                │
└────────────────────────────────────────────────────────────────────┘
```

### 5.2 Bundle Layout (Revised)

```
sentinelcore-rules-2026.03.01.tar.gz
├── manifest.json                        # Artifact checksums + metadata
├── manifest.json.sig                    # Ed25519 signature by signing key
├── signing_key_cert.json                # Signing key certificate
├── signing_key_cert.json.sig            # Root key signature over certificate
├── revocations.json                     # Current revocation list
├── revocations.json.sig                 # Root key signature over revocations
├── sast/
│   └── rules.jsonl
└── dast/
    └── rules.jsonl
```

```
sentinelcore-platform-1.3.0.tar.gz
├── manifest.json
├── manifest.json.sig
├── signing_key_cert.json
├── signing_key_cert.json.sig
├── revocations.json
├── revocations.json.sig
├── images/
│   ├── sentinelcore-controlplane-1.3.0.tar
│   ├── sentinelcore-orchestrator-1.3.0.tar
│   └── ...
├── helm/
│   └── sentinelcore-1.3.0.tgz
└── migrations/
    └── 1.2.0_to_1.3.0.sql
```

### 5.3 Manifest Format (Revised)

```json
{
  "format": "sentinelcore-bundle-manifest",
  "format_version": 2,
  "bundle_type": "rules",
  "version": "2026.03.01",
  "created_at": "2026-03-01T10:00:00Z",
  "min_platform_version": "1.2.0",
  "signing_key_serial": "SKC-2026-RULE-001",
  "artifacts": [
    {
      "path": "sast/rules.jsonl",
      "sha256": "a1b2c3...",
      "size_bytes": 1048576
    },
    {
      "path": "dast/rules.jsonl",
      "sha256": "d4e5f6...",
      "size_bytes": 524288
    }
  ],
  "previous_version": "2026.02.15",
  "rollback_safe": true
}
```

Key addition: `signing_key_serial` links the manifest to the specific signing key certificate in the bundle, preventing substitution of a different certificate.

---

## 6. Bundle Verification Flow (Customer Side)

### 6.1 Full Verification Algorithm

```
VERIFY_BUNDLE(bundle_path, pinned_root_pubkey):

  ── Phase 1: Extract and parse ──────────────────────────────────
  1.  Extract bundle to quarantine directory
  2.  Read: manifest.json, manifest.json.sig,
            signing_key_cert.json, signing_key_cert.json.sig,
            revocations.json, revocations.json.sig

  ── Phase 2: Process revocations first ──────────────────────────
  3.  Verify revocations.json.sig against pinned_root_pubkey
  4.  If revocations.sequence > local_stored_sequence:
        Update local revocation list
  5.  Merge bundle revocation list with local revocation list
        (union of all revoked serials)

  ── Phase 3: Verify signing key certificate ─────────────────────
  6.  Verify signing_key_cert.json.sig against pinned_root_pubkey
        → This proves the signing key was authorized by root
  7.  Assert signing_key_cert.issued_by_root_fingerprint
        == sha256(pinned_root_pubkey)
  8.  Assert signing_key_cert.serial NOT IN merged revocation list
  9.  Assert signing_key_cert.valid_from ≤ now + 48h grace
  10. Assert signing_key_cert.valid_until ≥ now - 48h grace
  11. Assert signing_key_cert.purpose matches bundle_type:
        platform_signing   → bundle_type in {platform}
        rule_signing       → bundle_type in {rules}
        vuln_intel_signing → bundle_type in {vuln_intel}

      Special cases for key_rotation and emergency_revocation bundles:
        a. If bundle_type in {key_rotation, emergency_revocation}:
           - Accept ANY valid signing key purpose as the signer, OR
           - Accept root-signed manifest if manifest contains
             "signed_by_root": true (verify manifest.json.sig
             against pinned_root_pubkey instead of signing_pubkey)
        b. If manifest contains "emergency_signer_purpose":
           - Accept cross-purpose signing ONLY when the bundle's
             revocation list revokes the original key for this purpose
  12. Extract signing_pubkey from verified certificate
      (or use pinned_root_pubkey if root-signed manifest)

  ── Phase 4: Verify bundle signature ────────────────────────────
  13. Read manifest.json
  14. Assert manifest.signing_key_serial == signing_key_cert.serial
        → Prevents certificate substitution
  15. Compute canonical_bytes = canonicalize(manifest.json)  [Section 3.3]
  16. Verify ed25519_verify(signing_pubkey, canonical_bytes, manifest.json.sig)
        → Same canonicalize-then-sign-directly pattern as certificates
  17. Parse manifest.json

  ── Phase 5: Verify artifact integrity ──────────────────────────
  18. For each artifact in manifest.artifacts:
        a. Compute sha256(artifact_file)
        b. Assert computed hash == manifest.artifacts[i].sha256
        c. Assert file size == manifest.artifacts[i].size_bytes
  19. Assert no extra files exist in bundle beyond manifest entries
        + known metadata files (manifest, sigs, cert, revocations)

  ── Phase 6: Version and compatibility checks ───────────────────
  20. Assert manifest.version > currently_installed_version
        → Rollback protection (monotonic version enforcement)
        → Override: sentinelcore-cli update rollback (see Section 12.3)
  21. Assert current_platform_version >= manifest.min_platform_version
        → Compatibility guard
  22. For platform bundles: validate migration path
        (manifest.min_upgrade_from ≤ current_version)

  ── Phase 7: Accept ─────────────────────────────────────────────
  23. Move bundle to staging area
  24. Log audit event: "update.verified" with full verification chain
  25. Await admin approval before application

  On ANY verification failure:
    - Log detailed error with step number and expected vs. actual values
    - Alert operator
    - Reject bundle
    - Delete quarantine directory
    - Log audit event: "update.verification_failed"
```

### 6.2 Verification Decision Diagram

```
Bundle received
     │
     ▼
Revocation list signature valid?  ──NO──► REJECT
     │ YES
     ▼
Update local revocation list
     │
     ▼
Signing key cert signature valid?  ──NO──► REJECT
     │ YES
     ▼
Signing key cert serial revoked?  ──YES──► REJECT
     │ NO
     ▼
Signing key cert within validity window?  ──NO──► REJECT
     │ YES
     ▼
Signing key purpose matches bundle type?  ──NO──► REJECT
     │ YES
     ▼
Manifest signature valid (via signing key)?  ──NO──► REJECT
     │ YES
     ▼
Manifest references correct cert serial?  ──NO──► REJECT
     │ YES
     ▼
All artifact SHA-256 hashes match?  ──NO──► REJECT
     │ YES
     ▼
Version > installed? Compatible?  ──NO──► REJECT
     │ YES
     ▼
STAGE for admin approval
```

---

## 7. Key Rotation

### 7.1 Annual Signing Key Rotation (Normal Operation)

This is the routine case. Performed annually per signing key purpose.

**Vendor-side ceremony:**

```
Participants required: 2-of-3 from {security-lead, engineering-lead, compliance-officer}
Location: Secure facility with HSM access
Duration: ~2 hours

Steps:
1.  Generate new Ed25519 key pair on HSM (key never leaves HSM)
2.  Export new public key from HSM
3.  Construct signing_key_certificate JSON:
    - serial: next in sequence (e.g., SKC-2027-PLAT-001)
    - purpose: same as predecessor
    - public_key: new public key
    - valid_from: overlap start (30 days before old cert expires)
    - valid_until: +1 year from valid_from
    - replaces_serial: old certificate serial
4.  Authenticate 2-of-3 ceremony participants to HSM
5.  Sign certificate with root private key on HSM
6.  Verify signature with root public key (independent workstation)
7.  Package: signing_key_cert.json + signing_key_cert.json.sig
8.  Distribute new certificate:
    a. Include in next bundle for each affected bundle type
    b. For air-gapped: produce standalone key rotation bundle
9.  Log ceremony in vendor audit system with ceremony_id
10. Retain old signing key for 30-day overlap window
    (old key can still sign during overlap for pipeline continuity)
11. After overlap: archive old signing key on HSM (marked inactive)
```

**Customer-side processing:**

When a bundle arrives containing a new signing key certificate:
1. Existing verification flow (Section 6.1) validates the new certificate against the pinned root key
2. New certificate is stored locally alongside the old one
3. Both are valid during the overlap window
4. After old certificate's `valid_until` passes, it is automatically pruned from local storage
5. Audit event: `signing_key_rotated`

**No customer action required for normal rotation.** The root key signature on the new certificate is the proof of authority.

### 7.2 Key Rotation Bundle (Standalone)

For delivering new signing key certificates outside of a regular update (e.g., emergency rotation, or air-gapped environments that won't receive a regular update soon):

```
sentinelcore-key-rotation-2026-03-14.tar.gz
├── manifest.json
│   {
│     "format": "sentinelcore-bundle-manifest",
│     "format_version": 2,
│     "bundle_type": "key_rotation",
│     "version": "2026.03.14",
│     "created_at": "...",
│     "signing_key_serial": "SKC-2026-PLAT-001",
│     "artifacts": [
│       {"path": "new_signing_key_cert.json", "sha256": "...", "size_bytes": ...},
│       {"path": "new_signing_key_cert.json.sig", "sha256": "...", "size_bytes": ...}
│     ]
│   }
├── manifest.json.sig                          # Signed by CURRENT signing key
├── signing_key_cert.json                      # CURRENT signing key cert (for chain)
├── signing_key_cert.json.sig
├── revocations.json
├── revocations.json.sig
├── new_signing_key_cert.json                  # NEW signing key cert
└── new_signing_key_cert.json.sig              # Signed by ROOT key
```

**Normal rotation:** The key rotation bundle manifest is signed by the **current** signing key (proving it came through the authorized pipeline) and contains a **new** signing key certificate signed by the **root** key. Both layers must verify.

**Emergency rotation (current signing key compromised):** The compromised signing key cannot be used. In this case:

1. **Cross-purpose signing:** If the rule signing key is compromised, the manifest of the emergency bundle is signed by the platform signing key (or vice versa). The manifest includes a field `emergency_signer_purpose` to indicate this cross-purpose use. The verification algorithm accepts this cross-purpose signature ONLY when the bundle also contains a revocation list that revokes the original signing key for that purpose.
2. **Root-signed manifest (last resort):** If multiple signing keys are compromised simultaneously, the manifest is signed directly by the root key. The manifest includes `"signed_by_root": true`. The verification algorithm accepts root-signed manifests only for `bundle_type: "key_rotation"` or `bundle_type: "emergency_revocation"`.

The new signing key certificate inside the bundle is always signed by the root key regardless of which key signs the manifest. The root-signed certificate is the authoritative proof — the manifest signature is a pipeline-integrity check, not the trust anchor.

### 7.3 Root Key Rotation (Emergency Only)

Root key rotation is an extraordinary event triggered only by confirmed or suspected root key compromise. It cannot be automated.

**This is the one scenario that requires customer action.**

```
Trigger: Confirmed root key compromise
Response time target: 24 hours from detection to advisory publication

Vendor steps:
1.  Activate incident response team
2.  Generate new root key pair on new HSM (or reserve HSM partition)
3.  Issue new signing key certificates under new root
4.  Publish security advisory via:
    - Direct customer contact (email, phone for critical accounts)
    - Security advisory page (signed with PGP key registered with customers)
    - CVE assignment if applicable
5.  Provide customers with:
    - New root public key (hex-encoded, multiple formats)
    - PGP-signed advisory containing the new key fingerprint
    - Verification instructions

Customer steps:
1.  Receive advisory, verify PGP signature
2.  Verify root public key fingerprint via independent channel
    (phone call to vendor security team, in-person verification for
    critical deployments)
3.  Pin new root key:
    sentinelcore-cli update pin-root-key \
      --key <base64-new-root-public-key> \
      --old-key-fingerprint <sha256-of-compromised-root> \
      --reason "vendor advisory SA-2026-001" \
      --confirm-emergency
4.  This command:
    - Writes new root public key to /var/lib/sentinelcore/trust/root_pubkey.pem
    - Moves old root public key to revoked_roots/
    - Creates audit event: "root_key_pinned" with full details
    - Requires platform_admin or break-glass access
    - Prompts for confirmation with displayed fingerprint
5.  Subsequent bundle verification uses new root key
```

**Residual risk:** Customer must trust the out-of-band channel (PGP-signed advisory, phone verification). This is inherent to any root-of-trust rotation and cannot be eliminated cryptographically.

---

## 8. Key Compromise Response Procedures

### 8.1 Signing Key Compromise

**Severity: HIGH. Blast radius: one bundle type.**

```
Timeline: Detection to containment < 4 hours

Vendor response:
  Hour 0:    Confirm compromise. Disable compromised signing key on HSM.
  Hour 0-1:  Generate new signing key. Root-sign new certificate.
  Hour 1-2:  Add compromised certificate serial to revocation list.
             Root-sign updated revocation list.
  Hour 2-3:  Build emergency revocation bundle containing:
             - Updated revocations.json (root-signed)
             - New signing key certificate (root-signed)
  Hour 3-4:  Distribute revocation bundle:
             - Push to online update channel
             - Publish to customer portal for offline download
             - Direct notification to air-gapped customers
  Hour 4+:   Investigate scope. Determine if any malicious bundles
             were signed. If yes: publish advisory with affected
             versions and remediation steps.

Customer impact:
  - Online: automatic revocation list update on next check
  - Air-gapped: manual revocation bundle import required
  - Bundles signed by compromised key after compromise date
    are rejected once revocation list is updated
  - Bundles signed BEFORE compromise date remain valid
    (they were signed by the legitimate key at the time)
```

### 8.2 Build Pipeline Compromise (Key Not Stolen)

**Severity: HIGH. Signing key is intact but malicious content was signed.**

```
Vendor response:
  1. Revoke the specific bundle versions, not the signing key
  2. Publish advisory listing affected bundle versions
  3. Update revocation list with version-level revocation
     (extend revocation format — see 8.4 below)
  4. Publish clean replacement bundles

This scenario does NOT require signing key rotation because the key
itself is not compromised — only the build pipeline was.
```

### 8.3 Root Key Compromise

**Severity: CRITICAL. Blast radius: entire update chain.**

```
Vendor response:
  Hour 0:     Confirm compromise. Shut down all signing infrastructure.
  Hour 0-4:   Generate new root key on isolated HSM.
              Re-issue all signing key certificates under new root.
  Hour 4-8:   Prepare customer advisory:
              - New root public key
              - PGP-signed announcement
              - Step-by-step re-pinning instructions
  Hour 8-12:  Direct customer outreach (phone/email for all accounts).
  Hour 12-24: Publish advisory publicly.
              Distribute new bundles signed under new root.

Customer side:
  On receiving advisory:
  1. IMMEDIATELY enter update lockdown:
     sentinelcore-cli update lockdown --enable
     → Rejects ALL incoming bundles until lockdown is lifted
  2. Verify advisory authenticity via independent channel
  3. Pin new root key (Section 7.3)
  4. Lift lockdown:
     sentinelcore-cli update lockdown --disable
  5. Import new bundles signed under new root

Air-gapped customers:
  - Must receive advisory via out-of-band channel
  - Must receive new root key via secure courier or in-person
  - All pending bundle transfers on media should be discarded
    and re-provisioned with bundles signed under new root
```

### 8.4 Version-Level Revocation (Extension)

For build pipeline compromises where the key is intact but specific bundles are malicious, extend the revocation list with `format_version: 2`:

**Revocation list version history:**
- `format_version: 1` — fields: `revoked_certificates`, `revoked_root_keys`
- `format_version: 2` — adds: `revoked_bundles` (version-level revocation)

Parsers MUST reject unknown `format_version` values. Parsers supporting v2 MUST also accept v1 (v1 lists simply have no `revoked_bundles`).

```json
{
  "format": "sentinelcore-revocation-list",
  "format_version": 2,
  "issued_at": "2026-03-14T00:00:00Z",
  "sequence": 48,
  "revoked_certificates": [],
  "revoked_bundles": [
    {
      "bundle_type": "rules",
      "version": "2026.02.15",
      "revoked_at": "2026-03-14T00:00:00Z",
      "reason": "pipeline_compromise",
      "advisory": "SA-2026-002"
    }
  ],
  "revoked_root_keys": []
}
```

Update Manager checks `revoked_bundles` against installed versions. If the currently installed version of a bundle type is revoked:
1. Alert operator: "Installed bundle version has been revoked"
2. Block scans that depend on the revoked bundle (e.g., if rules are revoked, block scans using those rules)
3. Await replacement bundle installation

---

## 9. Bootstrap Trust Establishment

### 9.1 Initial Installation

The root public key is the trust anchor. It must be established before any update verification can occur.

```
Installation media (Helm chart / OCI bundle / air-gap archive) contains:
├── sentinelcore-1.0.0.tgz            # Helm chart
├── images/                             # Container images
├── trust/
│   ├── root_pubkey.json               # Root public key
│   │   {
│   │     "format": "sentinelcore-root-public-key",
│   │     "format_version": 1,
│   │     "key_id": "ROOT-2026-001",
│   │     "public_key": "<base64-ed25519-public-key>",
│   │     "fingerprint": "sha256:<hex>",
│   │     "created_at": "2026-01-01T00:00:00Z"
│   │   }
│   ├── platform_signing_cert.json     # Initial platform signing key cert
│   ├── platform_signing_cert.json.sig
│   ├── rule_signing_cert.json         # Initial rule signing key cert
│   ├── rule_signing_cert.json.sig
│   ├── vuln_intel_signing_cert.json   # Initial vuln intel signing key cert
│   ├── vuln_intel_signing_cert.json.sig
│   └── revocations.json              # Initial (empty) revocation list
│   └── revocations.json.sig
├── rules/                             # Initial rule packs (signed)
└── vuln-intel/                        # Initial vuln intel (signed, optional)
```

### 9.2 Bootstrap Sequence (Trust-Relevant Steps)

```
Phase 1: Helm install
  1. Helm chart deploys Update Manager with trust/ directory contents
     mounted as a read-only volume
  2. Update Manager init container:
     a. Reads root_pubkey.json → stores to /var/lib/sentinelcore/trust/root_pubkey.json
     b. Verifies all signing key certificates against root public key
     c. Stores verified signing key certificates
     d. Stores initial revocation list
     e. Writes bootstrap trust state: "trust_established"
  3. If any certificate verification fails: init container exits with error,
     pod does not start, operator must verify installation media integrity

Phase 2: sentinelcore-cli bootstrap
  4. Operator runs bootstrap CLI (Section 10 of remediation architecture)
  5. CLI displays root key fingerprint and prompts operator to verify:
     "Root public key fingerprint: sha256:a1b2c3d4...
      Verify this matches the fingerprint on your installation receipt.
      Continue? [y/N]"
  6. This human verification step is the TOFU (Trust On First Use) moment —
     the operator is asserting that the installation media is authentic
```

### 9.3 Trust On First Use (TOFU) Model

```
Trust chain at bootstrap:

  Physical installation media (DVD, USB, secure download with checksum)
       │
       │ Operator verifies media authenticity
       │ (vendor-provided checksum, GPG signature on download, or physical chain of custody)
       │
       ▼
  Root public key on installation media
       │
       │ Bootstrap CLI displays fingerprint for human verification
       │
       ▼
  Root public key pinned in /var/lib/sentinelcore/trust/
       │
       │ All subsequent verification chains from this anchor
       │
       ▼
  Signing key certificates ──► Bundle signatures ──► Artifact integrity
```

**The root public key fingerprint MUST be published through a separate channel from the installation media itself** — for example:
- Printed on the physical order documentation
- Published on the vendor security page (accessible via HTTPS to a different domain)
- Available via vendor support phone line

This allows the operator to perform an independent verification that the root key in their installation media has not been tampered with.

---

## 10. Customer-Side Trust Store

### 10.1 File Layout

```
/var/lib/sentinelcore/trust/
├── root_pubkey.json                     # Pinned root public key
├── signing_certs/
│   ├── platform/
│   │   ├── SKC-2026-PLAT-001.json       # Current platform signing cert
│   │   └── SKC-2026-PLAT-001.json.sig
│   ├── rules/
│   │   ├── SKC-2026-RULE-001.json
│   │   └── SKC-2026-RULE-001.json.sig
│   └── vuln_intel/
│       ├── SKC-2026-VINT-001.json
│       └── SKC-2026-VINT-001.json.sig
├── revocations.json                     # Current revocation list
├── revocations.json.sig
├── revoked_roots/                       # Archived revoked root keys (if any)
└── trust.state                          # Machine-readable trust state
```

### 10.2 Trust State File

```json
{
  "trust_established_at": "2026-01-15T10:00:00Z",
  "root_key_fingerprint": "sha256:a1b2c3...",
  "root_key_id": "ROOT-2026-001",
  "active_signing_certs": {
    "platform_signing": "SKC-2026-PLAT-001",
    "rule_signing": "SKC-2026-RULE-001",
    "vuln_intel_signing": "SKC-2026-VINT-001"
  },
  "revocation_sequence": 47,
  "last_verification_at": "2026-03-14T08:00:00Z",
  "lockdown": false
}
```

### 10.3 Trust Store Integrity

The trust store directory is critical — if an attacker can write to it, they can pin their own root key.

Protections:
1. **Filesystem permissions:** owned by `sentinelcore-updater` user (UID dedicated to Update Manager). No other service user has write access.
2. **Kubernetes volume:** mounted as a PersistentVolumeClaim used only by the Update Manager pod. No other pod mounts this PVC.
3. **Startup self-check:** Update Manager verifies on startup that root_pubkey.json has not changed since `trust_established_at` by comparing its hash against a hash stored in Vault (separate secret, accessible only to Update Manager). This check covers the entire trust store directory — root key, active signing certificates, and revocation list.
4. **Lockdown state in database, not filesystem:** The `lockdown` flag is stored in the `updates.trust_state` database table (Section 11.5), not in `trust.state` file. The file-based `trust.state` is a read cache only — the database is authoritative. This prevents a filesystem attacker from silently disabling lockdown mode.
5. **Audit:** every write to the trust store is audit-logged, including the caller, action, and file hash before/after.

---

## 11. Data Model Changes

### 11.1 New Table: `updates.signing_key_certificates`

```sql
CREATE TABLE updates.signing_key_certificates (
    serial          TEXT PRIMARY KEY,
    purpose         TEXT NOT NULL CHECK (purpose IN (
                        'platform_signing', 'rule_signing', 'vuln_intel_signing')),
    public_key      TEXT NOT NULL,                -- base64-encoded Ed25519 public key
    valid_from      TIMESTAMPTZ NOT NULL,
    valid_until     TIMESTAMPTZ NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL,
    root_fingerprint TEXT NOT NULL,               -- sha256 of root key that signed it
    replaces_serial TEXT REFERENCES updates.signing_key_certificates(serial),
    certificate_json TEXT NOT NULL,               -- full certificate JSON (for re-verification)
    signature       TEXT NOT NULL,                -- root key signature
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'expired', 'revoked', 'superseded')),
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_signing_certs_purpose_status
    ON updates.signing_key_certificates(purpose, status);
```

### 11.2 New Table: `updates.revocation_entries`

```sql
CREATE TABLE updates.revocation_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_type      TEXT NOT NULL CHECK (entry_type IN (
                        'certificate', 'bundle', 'root_key')),
    -- For certificate revocation:
    revoked_serial  TEXT,                          -- signing key cert serial
    -- For bundle revocation:
    revoked_bundle_type TEXT,
    revoked_bundle_version TEXT,
    -- Common fields:
    revoked_at      TIMESTAMPTZ NOT NULL,
    reason          TEXT NOT NULL,
    advisory_id     TEXT,                          -- vendor advisory reference
    revocation_sequence INTEGER NOT NULL,          -- from revocation list
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_revocation_serial ON updates.revocation_entries(revoked_serial)
    WHERE entry_type = 'certificate';
CREATE INDEX idx_revocation_bundle ON updates.revocation_entries(revoked_bundle_type, revoked_bundle_version)
    WHERE entry_type = 'bundle';
```

### 11.3 Modified Table: `updates.update_history` (Add Trust Fields)

Add the following columns to the existing update tracking table:

```sql
ALTER TABLE updates.update_history ADD COLUMN signing_key_serial TEXT;
ALTER TABLE updates.update_history ADD COLUMN manifest_hash TEXT;      -- sha256 of manifest.json
ALTER TABLE updates.update_history ADD COLUMN verification_chain JSONB;
-- verification_chain stores:
-- {
--   "root_fingerprint": "sha256:...",
--   "signing_cert_serial": "SKC-2026-RULE-001",
--   "signing_cert_verified": true,
--   "manifest_signature_verified": true,
--   "artifact_hashes_verified": true,
--   "revocation_checked": true,
--   "verified_at": "2026-03-14T..."
-- }
```

### 11.4 New Table: `updates.trust_events`

```sql
CREATE TABLE updates.trust_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type      TEXT NOT NULL CHECK (event_type IN (
                        'trust_established', 'signing_key_rotated',
                        'signing_key_revoked', 'bundle_revoked',
                        'root_key_pinned', 'lockdown_enabled',
                        'lockdown_disabled', 'verification_failed')),
    details         JSONB NOT NULL,
    actor_id        UUID,                          -- user who triggered (null for automatic)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 11.5 New Table: `updates.trust_state`

Authoritative source for lockdown flag and installed version counters. The file-based `trust.state` (Section 10.2) is a read cache — the database is the source of truth. This prevents filesystem tampering from silently disabling lockdown.

```sql
CREATE TABLE updates.trust_state (
    key             TEXT PRIMARY KEY,              -- e.g., 'lockdown', 'installed_version_rules'
    value           TEXT NOT NULL,
    updated_by      UUID,                          -- user or null for system
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed at bootstrap:
INSERT INTO updates.trust_state (key, value) VALUES
    ('lockdown', 'false'),
    ('root_key_fingerprint', ''),
    ('installed_version_platform', '0.0.0'),
    ('installed_version_rules', '0.0.0'),
    ('installed_version_vuln_intel', '0.0.0'),
    ('revocation_sequence', '0');
```

---

## 12. Update Manager Service Changes

### 12.1 New Responsibilities

The Update Manager (Section 5.16) gains:

| Responsibility | Description |
|---|---|
| Trust store management | Maintain `/var/lib/sentinelcore/trust/` and database trust tables |
| Certificate chain verification | Full Section 6.1 verification on every bundle |
| Revocation processing | Process and store revocation lists; enforce revocations |
| Key rotation handling | Accept and validate new signing key certificates |
| Lockdown mode | Reject all bundles when lockdown is active |
| Trust state monitoring | Expose metrics for certificate expiry, revocation status |

### 12.2 New gRPC API Endpoints

```protobuf
service UpdateManager {
  // Existing
  rpc CheckForUpdates(CheckRequest) returns (UpdateAvailability);
  rpc ImportBundle(ImportBundleRequest) returns (ImportResult);
  rpc ApplyUpdate(ApplyRequest) returns (ApplyResult);
  rpc RollbackUpdate(RollbackRequest) returns (RollbackResult);

  // New: trust management
  rpc GetTrustState(Empty) returns (TrustState);
  rpc ListSigningCertificates(ListCertsRequest) returns (CertificateList);
  rpc GetRevocationList(Empty) returns (RevocationList);
  rpc EnableLockdown(LockdownRequest) returns (LockdownResult);
  rpc DisableLockdown(LockdownRequest) returns (LockdownResult);
}
```

### 12.3 New CLI Commands

```
sentinelcore-cli update trust-status
  → Shows: root key fingerprint, active signing certs, revocation count,
           lockdown state, cert expiry dates

sentinelcore-cli update pin-root-key \
    --key <base64> \
    --old-key-fingerprint <sha256> \
    --reason <text> \
    --confirm-emergency
  → Requires: platform_admin or break-glass session
  → Audit logged

sentinelcore-cli update lockdown --enable
  → Immediately rejects all incoming bundles
  → Requires: platform_admin or break-glass session

sentinelcore-cli update lockdown --disable
  → Re-enables bundle processing
  → Requires: platform_admin

sentinelcore-cli update verify-bundle --bundle <path>
  → Dry-run verification of a bundle without importing
  → Outputs: full verification chain result

sentinelcore-cli update rollback \
    --bundle-type <platform|rules|vuln_intel> \
    --to-version <version> \
    --override-monotonicity \
    --reason <text>
  → Bypasses version monotonicity check (step 20) for this one import
  → Requires: platform_admin or break-glass session
  → Resets the installed-version counter for the specified bundle type
  → The target bundle still undergoes FULL cryptographic verification
    (only the version > installed check is skipped)
  → Audit logged with reason
```

### 12.4 New Metrics

| Metric | Type | Description |
|---|---|---|
| `sentinelcore_signing_cert_expiry_seconds` | Gauge (per purpose) | Seconds until active signing cert expires |
| `sentinelcore_signing_cert_age_seconds` | Gauge (per purpose) | Seconds since active signing cert was issued |
| `sentinelcore_revocation_list_sequence` | Gauge | Current revocation list sequence number |
| `sentinelcore_update_verification_total` | Counter (by result) | Bundle verifications: success, failed, revoked |
| `sentinelcore_trust_lockdown_active` | Gauge | 1 if lockdown is active, 0 otherwise |

### 12.5 New Alert Rules

| Alert | Severity | Condition |
|---|---|---|
| `SigningCertExpiryImminent` | HIGH | Any signing cert expires in < 30 days |
| `SigningCertExpired` | CRITICAL | Any signing cert has expired (updates of that type will fail) |
| `BundleVerificationFailed` | HIGH | Bundle verification failure (potential tampering) |
| `SigningKeyRevoked` | CRITICAL | A signing key has been revoked |
| `TrustLockdownActive` | HIGH | System is in update lockdown mode |
| `RootKeyMismatch` | CRITICAL | Root key in trust store doesn't match Vault-stored hash |

---

## 13. Operational Procedures

### 13.1 Annual Signing Key Rotation Runbook

**Pre-ceremony (1 week before):**
- [ ] Schedule ceremony with 2-of-3 authorized participants
- [ ] Verify HSM accessibility and firmware version
- [ ] Prepare air-gapped workstation for independent signature verification
- [ ] Notify customers of upcoming key rotation (informational — no action required)

**Ceremony:**
- [ ] Authenticate all participants to HSM
- [ ] Generate new Ed25519 key pair (HSM slot)
- [ ] Export public key
- [ ] Construct signing key certificate JSON
- [ ] Sign certificate with root key on HSM
- [ ] Verify signature on independent air-gapped workstation
- [ ] Record ceremony in vendor audit system
- [ ] Store ceremony artifacts (certificate, verification transcript)

**Post-ceremony:**
- [ ] Include new certificate in next build for affected bundle type
- [ ] For air-gapped customers: prepare standalone key rotation bundle
- [ ] Monitor customer-side metrics for rotation success
- [ ] After overlap window (30 days): mark old signing key as inactive on HSM

### 13.2 Emergency Signing Key Revocation Runbook

- [ ] Confirm compromise with evidence
- [ ] Disable compromised key on HSM
- [ ] Generate replacement signing key (ceremony or emergency pre-authorized)
- [ ] Root-sign new certificate
- [ ] Root-sign updated revocation list (increment sequence)
- [ ] Build emergency revocation bundle
- [ ] Distribute: online channel push, customer portal, direct notification
- [ ] Track customer adoption via support channels
- [ ] Post-incident review within 72 hours

### 13.3 Customer: Importing a Key Rotation Bundle

```bash
# 1. Download or receive the key rotation bundle
# 2. Verify (dry run)
sentinelcore-cli update verify-bundle --bundle ./sentinelcore-key-rotation-2026-03-14.tar.gz

# Expected output:
# ✓ Revocation list: valid (sequence 48)
# ✓ Signing key certificate: valid (serial SKC-2027-RULE-001)
# ✓ Manifest signature: valid
# ✓ New signing key certificate: valid, signed by root sha256:a1b2c3...
# Result: VERIFICATION PASSED

# 3. Import
sentinelcore-cli update import --bundle ./sentinelcore-key-rotation-2026-03-14.tar.gz

# 4. Verify trust state
sentinelcore-cli update trust-status
```

---

## 14. Air-Gapped Deployment Considerations

### 14.1 Unchanged Guarantees

The trust model operates identically in connected, semi-connected, and air-gapped modes. The Ed25519 signature verification requires no network access — all verification material is included in the bundle itself, and the trust anchor (root public key) is stored locally.

### 14.2 Air-Gap-Specific Guidance

| Concern | Handling |
|---|---|
| Clock drift | 48-hour grace window on certificate validity times. If drift exceeds 48h, operator must fix NTP before importing bundles. |
| Revocation delivery lag | Air-gapped sites may not receive revocation lists promptly. Compensating control: transfer station operators check vendor advisory page before importing any bundle. |
| Key rotation bundle delivery | Standalone key rotation bundles should be transferred alongside regular update bundles. Bundle checklist (Section 14.5.1 of deployment doc) updated to include trust material verification. |
| Root key pin override | `pin-root-key` command works locally — no network required. Operator must verify new root key fingerprint via independent channel (phone, in-person). |

### 14.3 Transfer Station Verification

The transfer station (Section 14.2 of deployment doc) adds trust verification to its checklist:

```
Existing:
  □ Bundle signature verified on connected workstation
  □ Bundle transferred to approved media
  □ Chain of custody form signed
  □ Media scanned for malware

Added:
  □ Signing key certificate in bundle matches current known-good serial
    (or is a valid rotation — verify against root fingerprint)
  □ Revocation list sequence ≥ previously known sequence
  □ No signing key revocations since last transfer
  □ Vendor advisory page checked for security notices (connected side)
```

---

## 15. Security Analysis

### 15.1 Attack Resistance

| Attack | Defeated by | Residual risk |
|---|---|---|
| Stolen signing key signs malicious bundle | Revocation via root key; blast radius limited to one bundle type | Window between compromise and revocation delivery to air-gapped sites |
| Attacker replays old valid bundle | Version monotonicity check (step 20 of verification) | None — old versions are always rejected |
| Attacker modifies bundle in transit | SHA-256 artifact hashes in signed manifest | None — any modification is detected |
| Attacker substitutes signing key cert | Manifest links to specific cert serial (step 14 of verification) | None — substitution is detected |
| Attacker substitutes revocation list with older version | Monotonic sequence number; old list is rejected | None — downgrade is detected |
| Compromised vendor build pipeline signs malicious content | Version-level revocation (Section 8.4); detected by vendor monitoring | Window between compromise and detection |
| Attacker writes to customer trust store | Filesystem permissions + Vault hash check on startup | Root compromise of customer Kubernetes cluster (out of scope — if cluster is compromised, attacker has full control regardless) |
| Quantum computer breaks Ed25519 | Not mitigated in this design | Future concern. When post-quantum Ed25519 replacements stabilize, root key rotation can transition to a PQ algorithm. The infrastructure supports it because root rotation is an explicit procedure. |

### 15.2 Cryptographic Assumptions

| Property | Relies on |
|---|---|
| Bundle authenticity | Ed25519 unforgeability (256-bit security level) |
| Bundle integrity | SHA-256 collision resistance (128-bit security level) |
| Root trust anchor | TOFU + out-of-band fingerprint verification |
| Revocation freshness | Monotonic sequence numbers (not cryptographic) |
| Time-bound validity | Approximate clock correctness within 48 hours |

### 15.3 What This Design Does NOT Cover

| Out of scope | Why | Where it is covered |
|---|---|---|
| Build pipeline integrity | Key management cannot prevent signing malicious content if the build is compromised | Supply chain security (Section 7.8) — SBOM, reproducible builds, code review |
| Customer cluster security | If an attacker has root on the K8s cluster, they can bypass any application-level control | Deployment hardening (Section 13) |
| Vulnerability in verification code | A bug in the Ed25519 verification could bypass all checks | Code quality — use audited Ed25519 libraries (Go `crypto/ed25519`), not custom implementations |
| Social engineering of key ceremony | A coerced ceremony participant could generate a rogue signing key | Physical security, background checks — organizational controls, not technical |

---

## 16. Trade-offs

| Decision | Benefit | Cost |
|---|---|---|
| Offline root key in HSM | Root compromise requires physical HSM access | Annual ceremony requires in-person HSM access; cannot automate root operations |
| Separate signing keys per bundle type | Single key compromise limits blast radius | Three key ceremonies instead of one; three certificates to manage |
| 48-hour clock drift grace | Air-gapped deployments work with imprecise NTP | A revoked certificate remains usable for up to 48 hours after expiry in a drifted environment. **Effective maximum certificate lifetime:** stated 1 year + 30-day rotation overlap + 48h grace on each end = ~13 months + 4 days. Auditors should reference this effective lifetime. |
| Custom certificate format (not X.509) | Simple, auditable, no OpenSSL dependency | Non-standard; cannot use existing PKI tooling; must maintain custom verification code |
| Revocation via signed list (not OCSP/CRL) | Works fully offline | Revocation delivery is not real-time for air-gapped sites; lag between revocation and enforcement |
| Version monotonicity (no rollback) | Prevents replay attacks | Legitimate rollback requires explicit admin override command |
| JSON canonical serialization for signatures | Deterministic, language-agnostic | Must document and enforce canonical form; potential for implementation bugs if not tested |
| Root key rotation requires manual customer action | No automated mechanism that could be exploited | Operationally expensive; requires customer awareness and action during a crisis |

---

## 17. Implementation Priority

| Phase | Component | Effort |
|---|---|---|
| **MVP (before first release)** | Root key generation ceremony | 1 day |
| | Signing key certificate format + verification library (Go) | 3 days |
| | Bundle signing in build pipeline | 2 days |
| | Bundle verification in Update Manager | 3 days |
| | Trust store management + bootstrap | 2 days |
| | CLI commands: `trust-status`, `verify-bundle` | 1 day |
| | Database schema (Section 11) | 1 day |
| **Sprint 2** | Revocation list processing | 2 days |
| | Key rotation bundle format + handling | 2 days |
| | Lockdown mode | 1 day |
| | `pin-root-key` CLI command | 1 day |
| | Metrics and alerting (Section 12.4-12.5) | 1 day |
| **Sprint 3** | Air-gap transfer station verification updates | 1 day |
| | Operational runbooks (Section 13) | 2 days |
| | Version-level revocation (Section 8.4) | 1 day |
| | Integration tests: full rotation + revocation scenarios | 3 days |

**Total estimated implementation:** ~26 engineering days across 3 sprints.
