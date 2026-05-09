# DAST Replay Operations Runbook

Operations runbook for the DAST authentication replay subsystem. Audience:
on-call SRE / SecOps responding to DAST-replay alerts. Covers triage,
common failure modes, rollback playbook, escalation, and forensic access.

> Scope: bundles created via `dast record`, replayed by the auth-broker
> replay engine (`internal/authbroker/replay`), with circuit breaker state
> in `dast_replay_failures` and forensic screenshots in the MinIO bucket
> `dast-forensics`. Plan #6 (DAST internal GA) reference:
> `docs/superpowers/plans/2026-05-06-dast-internal-ga.md`.

---

## 1. Triage matrix

For every DAST replay alert, run the **first three commands** in this
table to gather state before deeper investigation. All commands assume
shell access to the SentinelCore deployment host with the standard
`sentinelcore_postgres`, `sentinelcore_controlplane`, and
`sentinelcore_minio` container names.

| Alert | First command (psql) | Second (logs) | Third (object store) |
|-------|----------------------|---------------|----------------------|
| **Circuit open** (`dast_replay_circuit_state == 1`) | `docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c "SELECT bundle_id, consecutive_failures, last_failure_at, last_error FROM dast_replay_failures WHERE consecutive_failures >= 3 ORDER BY last_failure_at DESC LIMIT 20;"` | `docker logs sentinelcore_controlplane --since 30m 2>&1 \| grep -E 'circuit\|replay'` | `docker exec sentinelcore_minio mc ls minio/dast-forensics/bundle/<bundle_id>/` |
| **Post-state mismatch** (`dast_replay_postate_mismatch_total` rate spike) | `docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c "SELECT bundle_id, last_error FROM dast_replay_failures WHERE last_error ILIKE '%post%state%' OR last_error ILIKE '%postate%' ORDER BY last_failure_at DESC LIMIT 20;"` | `docker logs sentinelcore_controlplane --since 30m 2>&1 \| grep -i 'post.state\|postate'` | `docker exec sentinelcore_minio mc ls minio/dast-forensics/bundle/<bundle_id>/ --recursive` |
| **Principal mismatch** (`dast_replay_principal_mismatch_total` rate spike) | `docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c "SELECT b.id, b.principal_claim, f.last_error FROM dast_replay_failures f JOIN dast_auth_bundles b ON b.id = f.bundle_id WHERE f.last_error ILIKE '%principal%' ORDER BY f.last_failure_at DESC LIMIT 20;"` | `docker logs sentinelcore_controlplane --since 30m 2>&1 \| grep -i principal` | `docker exec sentinelcore_minio mc ls minio/dast-forensics/bundle/<bundle_id>/ --recursive` |
| **Captcha-mark** (`captcha_in_flow=true`, replay impossible) | `docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c "SELECT id, target_host, status, captcha_in_flow FROM dast_auth_bundles WHERE captcha_in_flow = true AND status IN ('approved','pending_review','refresh_required') ORDER BY created_at DESC LIMIT 20;"` | `docker logs sentinelcore_controlplane --since 30m 2>&1 \| grep -i captcha` | n/a — no replay attempt is made |
| **Anomaly** (`dast_replay_anomaly_total` rate spike) | `docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c "SELECT bundle_id, last_failure_at, last_error FROM dast_replay_failures WHERE last_error ILIKE '%anomaly%' ORDER BY last_failure_at DESC LIMIT 20;"` | `docker logs sentinelcore_controlplane --since 30m 2>&1 \| grep -i anomaly` | `docker exec sentinelcore_minio mc ls minio/dast-forensics/bundle/<bundle_id>/ --recursive` |

Useful follow-ups for any alert:

```sql
-- Bundle row + lifecycle pointers (status, supersede chain).
SELECT id, target_host, status, captcha_in_flow, principal_claim,
       superseded_by, expires_at, last_used_at
  FROM dast_auth_bundles WHERE id = '<bundle_id>';

-- Live circuit state with the screenshot ref array length.
SELECT bundle_id, consecutive_failures, last_failure_at,
       jsonb_array_length(screenshot_refs) AS screenshots, last_error
  FROM dast_replay_failures WHERE bundle_id = '<bundle_id>';

-- Recent audit events for this bundle.
SELECT created_at, event_type, details
  FROM audit_events
 WHERE resource_id = '<bundle_id>'
 ORDER BY created_at DESC LIMIT 50;
```

Prometheus / Grafana cross-checks (see `deploy/grafana/dast-replay-dashboard.json`):

- `rate(dast_replay_total{result="success"}[5m]) / rate(dast_replay_total[5m])`
  — overall success rate.
- `dast_replay_circuit_state == 1` — currently open circuits.
- `rate(dast_replay_anomaly_total[5m])`,
  `rate(dast_replay_postate_mismatch_total[5m])`,
  `rate(dast_replay_principal_mismatch_total[5m])`
  — per-class failure rates.
- `rate(dast_credential_load_total{result="not_found"}[5m])` and
  `{result="decrypt_error"}` — credential failure shape.

---

## 2. Common failure modes

### 2.1 Circuit open — `consecutive_failures >= 3`

**Symptom:** replay attempts return immediately without contacting the
target. Metric `dast_replay_circuit_state{bundle_id="..."} == 1`.

Hypothesis tree:

1. **Credentials rotated upstream.** Most common. The vault key the
   bundle references is now stale on the target site.
   - Verify: `docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c "SELECT vault_key FROM dast_credential_secrets WHERE bundle_id = '<bundle_id>';"`
   - Cross-reference customer's secret manager ticket / CAB record.
   - **Recovery:** Operator with `recording_admin` role runs
     `sentinelcore-cli dast bundles re-record <id> --reason "creds rotated" --start-recording`,
     re-records, gets it approved (4-eyes), and the new bundle replaces
     the old one (status `superseded`, `superseded_by = <new_id>`).

2. **Target site UI changed (selector drift).** A button id or form
   selector captured during recording no longer resolves.
   - Verify: `last_error` contains `selector` or `timeout`. Pull a
     forensic screenshot (§5) — the screenshot will show the rendered
     page at the failure point.
   - **Recovery:** re-record (same as 1).

3. **Bundle expired but not yet flipped.** `expires_at < now()` but
   nightly `dast-cleanup` hasn't run.
   - Verify: `SELECT expires_at FROM dast_auth_bundles WHERE id = '<bundle_id>';`
   - **Recovery:** force expiry then re-record:
     `UPDATE dast_auth_bundles SET status = 'expired' WHERE id = '<bundle_id>';`
     then re-record.

4. **Network partition / target down.** All bundles for the same host
   start failing simultaneously.
   - Verify: `last_error` contains `dial tcp` or HTTP 5xx; correlate
     with target's status page.
   - **Recovery:** wait. After the target recovers, manually reset
     circuits via `POST /api/v1/dast/bundles/{id}/circuit/reset`
     (recording_admin role required, see PR B/plan #5).

### 2.2 Post-state hash mismatch

**Symptom:** rising `dast_replay_postate_mismatch_total`. Replay completes
the action sequence but the post-state hash does not match the recorded
expected hash.

Hypothesis tree:

1. **Page now returns a dynamic field** (CSRF token, timestamp)
   captured during the recording but not pinned via `min_wait_ms`.
   - Verify: forensic screenshot will show the post-state DOM. Diff
     against the recorded `expected_post_state_hash`.
   - **Recovery:** re-record with the new shape.

2. **A/B test or gradual rollout** moved the customer's account into
   the new variant.
   - Verify: customer ack of A/B group.
   - **Recovery:** re-record under the new variant; consider pinning
     the bundle to the variant via target_host suffix.

### 2.3 Principal mismatch

**Symptom:** rising `dast_replay_principal_mismatch_total`. The session
that came back belongs to a different principal than `principal_claim`
on the bundle.

Hypothesis tree:

1. **Wrong customer credentials in vault.** Operator added the vault
   row to the wrong bundle.
   - Verify: cross-reference `target_principal` on the bundle vs. the
     observed identity in the failure logs.
   - **Recovery:** rotate vault row; re-record only if the bundle was
     completed against the wrong account.

2. **Tenant isolation breach (security).** Audit event
   `dast.replay.principal_mismatch` should already be emitted —
   escalate immediately. See §4.

### 2.4 Captcha-mark

**Symptom:** bundle has `captcha_in_flow = true`. Replay refuses to run.

- Captcha breaks the determinism guarantee — this is by design.
- **Recovery:** none mechanically. Either negotiate a captcha bypass
  with the target (allow-list IP, service account), or move that
  target out of automated DAST.

### 2.5 Anomaly

**Symptom:** `dast_replay_anomaly_total` spike. The replay reached the
target but produced an anomalous response (timing, size, 4xx not in the
recorded set).

- Often correlates with WAF / bot-mitigation flagging the traffic.
- **Recovery:** review forensic screenshot, coordinate with customer's
  WAF team to allow-list the SentinelCore IP range, then re-record if
  the page shape changed.

---

## 3. Rollback playbook

All migrations have idempotent down scripts. Down scripts are at
`migrations/<NNN>_*.down.sql`. Apply with:

```
docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore \
  -f /migrations/<NNN>_<name>.down.sql
```

| Migration | What rolls back | Expected duration | Data loss |
|-----------|-----------------|-------------------|-----------|
| `047_dast_bundle_actions` | Drops the recorded actions JSONB column | < 1 s on tables < 10 k rows | **Recordings drop:** all recorded action sequences are lost; bundles still load via the encrypted blob path. Recordings must be re-captured. |
| `048_dast_credential_secrets` | Drops the entire `dast_credential_secrets` table | < 1 s | **Credentials drop:** every replay credential the platform stores is wiped. Bundles relying on `vault_key` actions cannot replay until operators re-add credentials via `dast credentials add`. |
| `049_dast_replay_hardening` | Drops `dast_replay_failures` table + `principal_claim` column | < 1 s | **Circuit history lost.** Bundles forget the open-circuit state and may attempt failing replays once before re-tripping. The `principal_claim` reverts to the implicit default; identity-binding checks become best-effort. |
| `050_dast_forensics` | Drops the `screenshot_refs` JSONB column from `dast_replay_failures` | < 1 s | **Forensic screenshot pointers dropped.** Existing PNGs in MinIO `dast-forensics` bucket are NOT deleted — they become orphaned objects (cleanup-worker still removes them after 7 days). Operators lose the DB-side index from bundle to screenshot keys; manual `mc ls minio/dast-forensics/bundle/<id>/` still works. |
| `051_dast_bundle_supersede` | Drops `superseded_by` column + removes `'superseded'` from the status check constraint | < 1 s **but fails if any row has `status='superseded'`** | **Re-record links lost.** Source bundles that were superseded forget their replacement chain. Pre-flight: `UPDATE dast_auth_bundles SET status = 'soft_deleted' WHERE status = 'superseded';` before applying the down. |

**Pre-flight every rollback:**

```sh
# Backup before destructive migrations.
docker exec sentinelcore_postgres pg_dump -U sentinelcore -d sentinelcore \
  --table=dast_auth_bundles --table=dast_replay_failures \
  --table=dast_credential_secrets --data-only \
  > /tmp/dast-rollback-$(date +%Y%m%dT%H%M%S).sql
```

**Migrate in reverse order.** If you intend to roll back 050, also
roll back 051 first (051 references `dast_auth_bundles` columns that
050 does not touch, but the application code expects both).

---

## 4. Escalation path

### 4.1 Severity ladder

| Trigger | Severity | Response |
|---------|----------|----------|
| 1 bundle circuit open for < 1 hour | P3 | On-call SRE; runbook §2.1; no wake-up |
| > 5 bundles circuit open in same customer in 15 min | P2 | Page primary on-call SRE; if not resolved in 30 min, escalate to DAST tech lead |
| `dast_replay_principal_mismatch_total > 0` for any tenant | P1 (security) | Page Security on-call immediately. Treat as potential tenant-isolation breach until disproved. |
| `dast_replay_anomaly_total` rate > 10/min sustained | P2 | Page primary on-call SRE; correlate with target's status page and SentinelCore egress IP |
| /metrics endpoint down on controlplane | P1 | Page primary on-call SRE; metrics blindness blocks all other triage |
| Mass forensic capture failures (chromedp errors in logs) | P3 | Ticket; degrades forensic coverage but does not affect replay correctness |

### 4.2 Evidence to gather before escalation

1. **DB snapshot** — relevant rows from `dast_auth_bundles`,
   `dast_replay_failures`, `dast_credential_secrets`. Use the pre-flight
   `pg_dump` above.
2. **MinIO ref list** — `docker exec sentinelcore_minio mc ls minio/dast-forensics/bundle/<id>/ --recursive` for each affected bundle.
3. **Audit slice** — `SELECT * FROM audit_events WHERE resource_id = '<bundle_id>' AND created_at > now() - interval '24 hours' ORDER BY created_at;`
4. **Controlplane logs slice** — `docker logs sentinelcore_controlplane --since 1h > /tmp/cp-<bundle_id>.log`
5. **Prometheus snapshot** — current values of all `dast_replay_*` and
   `dast_credential_load_*` series for the last 1h (export from
   Grafana or `curl <controlplane>:9090/metrics`).

### 4.3 Wake-up matrix

| Time window | Primary | Secondary |
|-------------|---------|-----------|
| 09:00–18:00 local | SentinelCore SRE rotation | DAST tech lead |
| 18:00–09:00 local | SentinelCore SRE rotation | DAST tech lead (P1 only) |
| Weekend | SRE on-call only (P1/P2) | DAST tech lead (P1 only, with explicit page) |

For P1 security events (`principal_mismatch` or evidence of cross-tenant
data exposure), page the Security on-call regardless of time; the SRE
on-call assists with data collection but Security owns the incident.

---

## 5. Forensic access — retrieving a screenshot

Forensic screenshots are PNG bytes encrypted with the platform KMS key
(envelope encryption, AAD = bundle UUID) and stored in the MinIO bucket
`dast-forensics` under `bundle/<bundle_id>/<timestamp>-<action_idx>.png.enc`.
Operators with the `dast.recording_admin` role and KMS key access can
retrieve and decrypt them.

### 5.1 Locate the screenshot

```sql
-- All screenshot refs for a bundle.
SELECT bundle_id, screenshot_refs
  FROM dast_replay_failures
 WHERE bundle_id = '<bundle_id>';
```

The `screenshot_refs` JSONB column is an array of MinIO object keys
(no leading slash, no bucket prefix).

### 5.2 Verify operator access

```sql
-- Confirm the operator has the recording_admin role.
SELECT user_id, role
  FROM dast_user_roles
 WHERE user_id = '<operator_user_id>'
   AND role = 'dast.recording_admin';
```

If absent, request an admin grant via the standard role-grant workflow
**before** retrieving forensic data — the audit log records the
retrieval and tying it to a non-authorised user is a compliance
violation.

### 5.3 Pull the encrypted blob

```sh
# Requires mc (MinIO client) configured against the cluster's MinIO.
KEY="bundle/<bundle_id>/<ts>-<idx>.png.enc"
docker exec sentinelcore_minio mc cp "minio/dast-forensics/${KEY}" /tmp/sc-forensic.enc
docker cp sentinelcore_minio:/tmp/sc-forensic.enc /tmp/sc-forensic.enc
```

### 5.4 Decrypt with the KMS

The serialized envelope on disk is JSON-encoded
(`{"ciphertext":"...base64...","iv":"...","wrapped_dek":"...","key_version":"..."}`)
matching `internal/kms.Envelope`. Decrypt via the controlplane's KMS
provider (script lives at `scripts/dast/decrypt-forensic.go`):

```sh
SENTINEL_KMS_MASTER_KEY="$(cat /opt/sentinelcore/secrets/kms-master.key)" \
  go run ./scripts/dast/decrypt-forensic.go \
  --bundle-id <bundle_id> \
  --in /tmp/sc-forensic.enc \
  --out /tmp/sc-forensic.png
```

The AAD bound at encrypt time is the bundle UUID string, so passing
the wrong `--bundle-id` returns an authentication-tag failure (which is
the desired behaviour — it prevents cross-bundle decryption).

### 5.5 Audit and dispose

Every forensic retrieval emits a `dast.recording.forensic_retrieved`
audit event automatically when accessed via the controlplane API. For
direct MinIO + KMS access (this runbook), the operator MUST:

1. Manually insert an audit row:
   ```sql
   INSERT INTO audit_events (event_type, resource_id, user_id, details, created_at)
   VALUES ('dast.recording.forensic_retrieved.manual',
           '<bundle_id>', '<operator_user_id>',
           jsonb_build_object('reason', '<incident-id>', 'ref', '<minio_key>'),
           now());
   ```
2. Delete `/tmp/sc-forensic.enc` and `/tmp/sc-forensic.png` after
   incident close (the cleanup-worker handles MinIO retention but
   local disk copies are operator-owned).
3. If the screenshot is attached to a customer-facing incident report,
   redact PII per the customer's data handling agreement.

---

## 6. Quick reference

```sh
# Live circuit state.
docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c \
  "SELECT bundle_id, consecutive_failures, last_failure_at FROM dast_replay_failures WHERE consecutive_failures >= 3;"

# Reset a circuit (recording_admin only — go via API for the audit trail).
curl -X POST -H "Authorization: Bearer $SENTINELCORE_TOKEN" \
  "https://sentinelcore.<host>/api/v1/dast/bundles/<bundle_id>/circuit/reset"

# Re-record a stale bundle.
sentinelcore-cli dast bundles re-record <bundle_id> --reason "creds rotated" --start-recording

# Pull metrics snapshot.
curl -s "http://controlplane:9090/metrics" | grep -E "^dast_(replay|credential)_"

# Tail controlplane DAST events.
docker logs -f sentinelcore_controlplane 2>&1 | grep -E "dast\.(replay|recording)"
```
