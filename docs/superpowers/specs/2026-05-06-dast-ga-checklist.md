# DAST Internal GA Checklist

**Status:** required for the DAST authentication subsystem to be promoted
from "feature-complete" to "internal GA". All eight items below MUST pass
before the GA tag is cut. Each item has an explicit pass criterion AND a
verification command/procedure that can be run by an SRE without DAST
domain knowledge.

**Owner:** DAST tech lead. **Reviewer:** SRE on-call lead.

**Plan reference:** `docs/superpowers/plans/2026-05-06-dast-internal-ga.md`.

---

## Item 1 — STRIDE pen-test harness passes against staging

**Pass criterion:** every test in `tests/pentest/stride/` reports
`status=PASS` in `tests/pentest/report.json` against the latest
staging deployment. No tests are skipped except those that legitimately
require absent infrastructure (e.g. `PT_DB_URL` for the RLS bypass test).

**Verification:**

```sh
SENTINELCORE_HOST=https://staging.sentinelcore.example \
SENTINELCORE_API_TOKEN="$(cat secrets/staging-api-token)" \
  ./tests/pentest/run.sh

jq '.failed' tests/pentest/report.json   # must print 0
jq '.passed' tests/pentest/report.json   # must equal .total
```

**Sign-off evidence:** attach `tests/pentest/report.json` (raw JSON) to
the GA ticket. Reject any GA promotion where `failed > 0`.

---

## Item 2 — Prometheus metrics endpoint exposes DAST series

**Pass criterion:** `GET /metrics` on the controlplane returns 200 and
the response body contains at minimum:
- `dast_replay_total` (counter vec by `result`)
- `dast_replay_circuit_state` (gauge vec by `bundle_id`)
- `dast_replay_anomaly_total`
- `dast_replay_postate_mismatch_total`
- `dast_replay_principal_mismatch_total`
- `dast_credential_load_total` (counter vec by `result`)

**Verification:**

```sh
curl -s http://controlplane:9090/metrics \
  | grep -E '^# (HELP|TYPE) dast_(replay|credential)_' \
  | sort -u
# Must list all six metrics above, each with its TYPE line.
```

**Sign-off evidence:** the grep output, plus a Grafana screenshot showing
the imported `deploy/grafana/dast-replay-dashboard.json` rendering live
data for an active customer.

---

## Item 3 — Forensic screenshot capture works end-to-end

**Pass criterion:** a deliberately failing replay (e.g. invalid bundle
target) produces (a) a row in `dast_replay_failures` with
`jsonb_array_length(screenshot_refs) >= 1`, (b) the corresponding object
present in MinIO bucket `dast-forensics`, and (c) the object decrypts
correctly when fed the bundle UUID as AAD.

**Verification:**

```sh
# 1. Trigger a failing replay via the staging test harness.
SENTINELCORE_HOST=... SENTINELCORE_API_TOKEN=... \
  go test -run TestForensicE2E ./tests/integration/dast/...

# 2. Verify DB-side ref persistence.
docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c \
  "SELECT bundle_id, jsonb_array_length(screenshot_refs) AS n_refs
     FROM dast_replay_failures
    WHERE bundle_id = '<test_bundle_id>';"
# n_refs must be >= 1.

# 3. Verify MinIO object presence.
docker exec sentinelcore_minio mc ls minio/dast-forensics/bundle/<test_bundle_id>/
# Must list at least one .png.enc object.

# 4. Decrypt round-trip (uses scripts/dast/decrypt-forensic.go).
SENTINEL_KMS_MASTER_KEY="$(cat /opt/sentinelcore/secrets/kms-master.key)" \
  go run ./scripts/dast/decrypt-forensic.go \
  --bundle-id <test_bundle_id> \
  --in /tmp/blob.enc --out /tmp/forensic.png
file /tmp/forensic.png   # must report PNG image data
```

**Sign-off evidence:** the four command outputs above. Bonus: confirm
the `forensics-cleanup-worker` removes the object after `OLDER_THAN`
elapses by setting `OLDER_THAN=1m` on a one-shot deploy.

---

## Item 4 — Successful replays do NOT capture screenshots (privacy gate)

**Pass criterion:** a successful replay produces zero screenshot
captures. Verified by the existing `TestSec10_ForensicsOnlyOnFailure`
regression test in `internal/dast/security_regression_replay_test.go`.

**Verification:**

```sh
go test ./internal/dast/ -run TestSec10_ForensicsOnlyOnFailure -v -count=1
# Must report PASS.
```

**Sign-off evidence:** test output. This gate is the explicit privacy
contract that distinguishes DAST forensics from passive observability:
we never capture customer pages on the happy path.

---

## Item 5 — Re-record workflow round-trips end-to-end

**Pass criterion:** an operator with the `dast.recording_admin` role
can run `sentinelcore-cli dast bundles re-record <id>` against a live
bundle, the source flips to `status='superseded'` with `superseded_by`
set, and a fresh `pending_review` draft appears for re-recording.

**Verification:**

```sh
# Pre: pick an approved bundle id.
BUNDLE=$(docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -tA -c \
  "SELECT id FROM dast_auth_bundles WHERE status='approved' LIMIT 1;")

# 1. Run re-record CLI.
SENTINELCORE_TOKEN=... \
SENTINELCORE_API=https://staging.sentinelcore.example \
  sentinelcore-cli dast bundles re-record "$BUNDLE" --reason "GA test"

# 2. Verify source row state.
docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c \
  "SELECT id, status, superseded_by FROM dast_auth_bundles WHERE id = '$BUNDLE';"
# status must equal 'superseded' and superseded_by must be non-NULL.

# 3. Verify the draft exists in pending_review.
docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c \
  "SELECT id, status, target_host
     FROM dast_auth_bundles
    WHERE id = (SELECT superseded_by FROM dast_auth_bundles WHERE id = '$BUNDLE');"
# status must equal 'pending_review' with target_host copied from source.

# 4. Re-record on already-superseded source must fail with 409.
sentinelcore-cli dast bundles re-record "$BUNDLE" 2>&1 | grep -q "409"
```

**Sign-off evidence:** captured stdout from steps 1–4. Bonus: assert the
`dast.recording.superseded` audit event is present.

---

## Item 6 — Operations runbook is published and accurate

**Pass criterion:** `docs/runbooks/dast-replay.md` exists and every
command/SQL query in it has been executed at least once against staging
without modification. Operators can follow §1 (triage), §3 (rollback),
and §5 (forensic access) without unstated context.

**Verification:**

1. Drive a synthetic alert in staging (force a circuit-open by
   recording a bundle with bad credentials and replaying 4+ times).
2. Hand the runbook to an SRE who has never touched DAST.
3. Time-box: SRE must reach root cause within 30 min using only the
   runbook's commands.
4. Capture any deviations / additions; fold back into the runbook
   before sign-off.

**Sign-off evidence:** SRE walkthrough notes attached to the GA ticket.
At minimum: confirmation that the triage matrix commands ran cleanly
and the rollback playbook's pre-flight `pg_dump` succeeded.

---

## Item 7 — Migrations 047–051 apply and rollback cleanly on a fresh DB

**Pass criterion:** starting from an empty Postgres instance, applying
all migrations 001 through 051 succeeds; then applying down migrations
051 → 050 → 049 → 048 → 047 in reverse succeeds without manual
intervention (subject to the documented pre-flight: any rows with
`status='superseded'` must be removed before applying 051.down).

**Verification:**

```sh
# Spin up a fresh Postgres.
docker run --rm -d --name pg-ga-test \
  -e POSTGRES_USER=sentinelcore -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB=sentinelcore -p 5433:5432 postgres:16

# Apply all up migrations.
for f in migrations/*.up.sql; do
  docker exec -i pg-ga-test psql -U sentinelcore -d sentinelcore < "$f" || {
    echo "FAIL: $f"; exit 1
  }
done

# Pre-flight 051 rollback: clear any superseded rows.
docker exec pg-ga-test psql -U sentinelcore -d sentinelcore -c \
  "UPDATE dast_auth_bundles SET status='soft_deleted' WHERE status='superseded';"

# Apply down migrations 047-051 in reverse order.
for n in 051 050 049 048 047; do
  docker exec -i pg-ga-test psql -U sentinelcore -d sentinelcore \
    < migrations/${n}_*.down.sql || { echo "FAIL: ${n}.down"; exit 1; }
done

docker rm -f pg-ga-test
echo "PASS: migrations round-trip clean"
```

**Sign-off evidence:** the script's final `PASS` line and the absence
of any "FAIL" line in the loop.

---

## Item 8 — Audit events emitted on every state-changing DAST operation

**Pass criterion:** a single end-to-end exercise (record -> approve ->
replay (success) -> replay (forced failure) -> re-record -> revoke)
produces audit rows for at minimum:

- `dast.recording.created`
- `dast.recording.approved`
- `dast.recording.used`
- `dast.recording.superseded`
- `dast.recording.revoked`
- `dast.recording.integrity_failed` (if a tampered bundle is exercised)

…each scoped to the same `resource_id` and tagged with the actor
`user_id` in the `details` field.

**Verification:**

```sh
# After the end-to-end exercise.
docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c \
  "SELECT event_type, count(*)
     FROM audit_events
    WHERE resource_id = '<test_bundle_id>'
      AND event_type LIKE 'dast.%'
    GROUP BY event_type
    ORDER BY event_type;"
# Must include each of the events listed above with count >= 1.
```

**Sign-off evidence:** the query result table. This item underwrites
the compliance narrative — internal GA without audit closure is not
defensible against a SOC 2 / ISO 27001 review.

---

## Sign-off block

```
Item 1  STRIDE pen-test harness passes ......... [ ] _____________ (DAST lead)
Item 2  Prometheus DAST metrics exposed ........ [ ] _____________ (SRE)
Item 3  Forensic screenshot e2e ................ [ ] _____________ (DAST lead)
Item 4  Privacy gate: no capture on success .... [ ] _____________ (Security)
Item 5  Re-record round-trip ................... [ ] _____________ (DAST lead)
Item 6  Runbook accuracy ....................... [ ] _____________ (SRE)
Item 7  Migrations apply + rollback ............ [ ] _____________ (SRE)
Item 8  Audit closure .......................... [ ] _____________ (Security)
```

All eight items checked → cut tag `dast-internal-ga-YYYYMMDD` from the
merged PR D head and announce on the internal channel.
