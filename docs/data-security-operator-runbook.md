# Data Security Operator Runbook (Phase 7)

Operational procedures for the data-security layer: key rotation,
role-split deployment, encrypted backups, incident response.

Target audience: on-call operators and the security officer.

---

## 1. Normal operation

- **Controlplane env**: `/opt/sentinelcore/env/sentinelcore.env`
- **Split-role passwords**: `/opt/sentinelcore/env/roles.env` (chmod 0600, owner sentinelcore)
- **AES / HMAC key material**: today, env-file backed (`SC_TIER0_*` vars);
  Vault takeover planned
- **Backup key**: `/opt/sentinelcore/env/backup.env` —
  `SC_BACKUP_AGE_RECIPIENTS` holds one or more age public keys

All catalog tables:

- `auth.aes_keys` — AES-256 master keys by purpose (sso, webhook, ...)
- `audit.hmac_keys` — audit chain signing keys
- `auth.apikey_peppers` — API key HMAC pepper versions

Each row records `vault_path` + `fingerprint`. The fingerprint is
SHA-256 of the raw key bytes; mismatch between catalog fingerprint
and the key fetched from vault_path means Vault was rotated without
updating the catalog (or vice versa) — treat as an incident.

---

## 2. Key rotation

All rotations use the same CLI pattern:

    sentinelcore-cli rotate <target> [--dry-run] [--print-secret]

### 2.1 Rotate AES (`aes/<purpose>`)

Use case: SSO client secret encryption has aged past its 90-day
schedule, or a new deploy exposed the old key somehow.

    sentinelcore-cli rotate aes/sso

Effect: INSERTs a row `(version=N+1, purpose='sso', ...)` in
`auth.aes_keys`. Controlplane picks it up within 60s (envelope cache
TTL). New encryptions use v+1 immediately. Existing rows keep
validating under v (pkg/crypto/envelope walks every version).

Manual re-encryption of stored ciphertexts happens in a separate
sweep:

    -- Example: re-encrypt SSO provider client_secrets.
    -- Lives in cmd/rotate-sweep (planned, not yet written).

When every `enc:v<N>:sso:...` row has been rewritten:

    UPDATE auth.aes_keys SET rotated_at = now() WHERE version = <N>;

Old key material STAYS in Vault/env — deletion is manual + dual-control
because a lost-and-found backup may still reference the old version.

### 2.2 Rotate audit HMAC (`hmac/audit`)

Use case: scheduled quarterly rotation; audit-service logs a
`audit.hmac_rotated` event.

    sentinelcore-cli rotate hmac/audit

No re-signing required: the verifier walks every version in
`audit.hmac_keys` when checking a row. New rows signed under v+1.

### 2.3 Rotate API key pepper (`apikey-pepper`)

Use case: suspected pepper leak, scheduled annual rotation.

    sentinelcore-cli rotate apikey-pepper

**Warning**: unlike AES/HMAC, pepper rotation invalidates every
existing `key_verifier`. Run the dual-read transition:

1. `sentinelcore-cli rotate apikey-pepper` — prints new vault path.
2. Set `SC_APIKEY_PEPPER_B64_V2` in `sentinelcore.env` ALONGSIDE the
   existing `SC_APIKEY_PEPPER_B64` (= v1).
3. Restart controlplane. `pkg/apikeys.Resolve` now tries v2 first,
   falls back to v1. New keys write v2 verifiers.
4. Announce **7-day forced-reissue window** to users. Users rotate
   their keys through the UI; each rotation writes a v2 verifier.
5. After 7 days: drop `SC_APIKEY_PEPPER_B64` env var, restart.
6. `UPDATE auth.apikey_peppers SET rotated_at = now() WHERE version = 1;`

---

## 3. DB role split (Wave 3 deploy)

One-time migration from monolithic `sentinelcore` role to four split
roles. Run once per environment.

### 3.1 Apply migration

    psql "$DATABASE_URL" -f migrations/037_db_roles.up.sql

Creates `sentinelcore_{controlplane,audit_writer,worker,readonly}`
with LOGIN and NULL passwords. Default-privilege inheritance takes
effect immediately so future migrations don't need re-grants.

### 3.2 Generate + set passwords

    sentinelcore-cli db-split-roles --generate > /tmp/roles.env
    install -o sentinelcore -g sentinelcore -m 0600 \
        /tmp/roles.env /opt/sentinelcore/env/roles.env
    shred -u /tmp/roles.env

    # Source and apply
    set -a; source /opt/sentinelcore/env/roles.env; set +a
    sentinelcore-cli db-split-roles --apply

### 3.3 Re-point service DSNs

Update `/opt/sentinelcore/env/sentinelcore.env` so each service uses
its dedicated role. Example:

    # Controlplane
    CONTROLPLANE_DATABASE_URL=postgres://sentinelcore_controlplane:<pw>@localhost:5432/sentinelcore

    # Audit service
    AUDIT_SERVICE_DATABASE_URL=postgres://sentinelcore_audit_writer:<pw>@localhost:5432/sentinelcore

    # SAST/DAST workers
    WORKER_DATABASE_URL=postgres://sentinelcore_worker:<pw>@localhost:5432/sentinelcore

    # Backup timer
    BACKUP_DATABASE_URL=postgres://sentinelcore_readonly:<pw>@localhost:5432/sentinelcore

Restart the stack. Verify:

    sentinelcore-cli db-split-roles --verify

Should print each role's `current_user` + the schemas it can USE.
Controlplane should NOT list `audit` as USAGE-granted beyond the
SELECT scope; audit_writer should ONLY list `audit`.

### 3.4 Revert

    psql "$DATABASE_URL" -f migrations/037_db_roles.down.sql

Drops the four roles. Services must already be re-pointed back at
the monolithic `sentinelcore` role BEFORE running this.

---

## 4. Encrypted backups

### 4.1 Provision age key

On the backup host (NOT production), one-time:

    age-keygen -o /etc/sentinelcore/backup-age.txt
    # Print the public key to put in /opt/sentinelcore/env/backup.env:
    grep "^# public key:" /etc/sentinelcore/backup-age.txt

Example `/opt/sentinelcore/env/backup.env`:

    DATABASE_URL=postgres://sentinelcore_readonly:<pw>@localhost:5432/sentinelcore
    SC_BACKUP_AGE_RECIPIENTS=age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Multiple recipients are supported (space-separated) so a backup can
be decrypted by either a primary key or an offline recovery key.

### 4.2 Install systemd units

    install -m 0644 deploy/systemd/sc-backup.service /etc/systemd/system/
    install -m 0644 deploy/systemd/sc-backup.timer   /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now sc-backup.timer
    systemctl list-timers sc-backup.timer

### 4.3 Manual backup

    sudo -u sentinelcore /usr/local/bin/sc-backup \
        --out /var/lib/sentinelcore/backups/adhoc-$(date -u +%Y%m%dT%H%M%SZ).sql.age \
        --db-url "$BACKUP_DATABASE_URL"

### 4.4 Restore

    # On the restore host, with the private age key available:
    age --decrypt -i backup-age.txt backup.sql.age | pg_restore \
        --no-owner --no-privileges \
        -d postgres://sentinelcore@localhost:5432/sentinelcore_restore

Validate row counts against a recent reference:

    psql "$DATABASE_URL" -c "SELECT count(*) FROM findings.findings"
    psql "$RESTORE_URL"  -c "SELECT count(*) FROM findings.findings"

---

## 5. Incident response

### 5.1 AES master key suspected leaked

1. `sentinelcore-cli rotate aes/<purpose>` — v+1 live within 60s.
2. Run the re-encryption sweep (manual SQL today) — re-encrypts every
   `enc:v<N>:<purpose>:...` row with v+1.
3. Audit recent decrypts: query `audit.audit_log` for `*.secret.decrypt`
   events since the suspected leak window.
4. Document in Linear + notify affected tenants (24h SLA).
5. After re-encrypt sweep: revoke the leaked version — delete vault
   path material, leave catalog row for chain-of-custody.

### 5.2 DB dump exfiltrated

- Pre-pepper migration: assume every API key compromised. Trigger
  global forced reissue via:

      UPDATE core.api_keys SET revoked = true WHERE revoked = false;

  then notify all users (email blast on file in governance.users).

- Post-pepper (Phase 7 ≥ Wave 2 applied): key material is not
  recoverable from the dump alone. Still rotate pepper and force
  reissue for defense-in-depth.

### 5.3 Audit HMAC key v<N> corrupted in Vault

1. `cmd/audit-service` logs `audit.integrity_failed` alerts on the
   affected partition.
2. Attempt restore from quarterly key backup:

      vault kv get -field=key sc/tier0/hmac/audit/v<N>

3. If unrecoverable: mark affected partitions as "attest-only" —
   chain broken but rows still usable with compliance officer
   sign-off. Document in security audit log.

### 5.4 Backup cipher key lost

1. Fall back to older quarterly backup (second age key).
2. Generate new age keypair, update `SC_BACKUP_AGE_RECIPIENTS`.
3. Take new baseline backup.
4. Old backups with the lost key are permanently unreadable —
   document as a gap in incident response.

---

## 6. Pen-test rehearsal

Quarterly:

    SENTINELCORE_URL=https://staging.sentinelcore.example \
    DATABASE_URL=postgres://sentinelcore@db/sentinelcore \
    PSQL_CONTROLPLANE=postgres://sentinelcore_controlplane:<pw>@db/sentinelcore \
    scripts/pentest-data-security.sh

Expected output: 5 PASS, 0 FAIL. Any FAIL is a real finding — open a
P1 incident, assign to the security officer, hold all non-critical
merges until resolved.

---

## 7. Reference

- Plan: `docs/superpowers/plans/2026-04-18-phase7-data-security.md`
- Secret path catalog: `docs/secret-path-catalog.md` (TODO)
- Tenant isolation patterns: `docs/tenant-isolation-patterns.md` (TODO)
- Migration 037: `migrations/037_db_roles.up.sql`
- Rotation CLI: `internal/cli/rotate.go`
- Backup tool: `cmd/backup/main.go`
- Systemd units: `deploy/systemd/sc-backup.{service,timer}`
- Pen-test script: `scripts/pentest-data-security.sh`
