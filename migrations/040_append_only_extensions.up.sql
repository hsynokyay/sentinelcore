BEGIN;

-- Phase 7 §5.4: Extend append-only protection to tamper-sensitive
-- tables beyond audit.audit_log.
--
-- Two patterns:
--   1. Full lockdown — NO UPDATE / NO DELETE ever. Used for append-only
--      history tables that must never be rewritten.
--      Reuses audit.prevent_mutation from migration 032.
--   2. Column lockdown — UPDATE allowed, but only on a whitelist of
--      operational columns. Identity + filter fields immutable.

-- --- findings.finding_state_transitions: full lockdown ------------------
--
-- Every finding status change generates a row here. Compliance needs
-- to prove the history was never edited after the fact.
DROP TRIGGER IF EXISTS state_transitions_no_update ON findings.finding_state_transitions;
DROP TRIGGER IF EXISTS state_transitions_no_delete ON findings.finding_state_transitions;
CREATE TRIGGER state_transitions_no_update
    BEFORE UPDATE ON findings.finding_state_transitions
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();
CREATE TRIGGER state_transitions_no_delete
    BEFORE DELETE ON findings.finding_state_transitions
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();

-- --- audit.export_jobs: column lockdown ---------------------------------
--
-- Status progresses queued → running → succeeded|failed — those
-- fields legitimately mutate. Everything identifying / filtering
-- the request must stay as written.
CREATE OR REPLACE FUNCTION audit.export_jobs_restrict()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.id            IS DISTINCT FROM OLD.id            THEN RAISE EXCEPTION 'export_jobs.id is immutable'            USING ERRCODE = 'insufficient_privilege'; END IF;
    IF NEW.org_id        IS DISTINCT FROM OLD.org_id        THEN RAISE EXCEPTION 'export_jobs.org_id is immutable'        USING ERRCODE = 'insufficient_privilege'; END IF;
    IF NEW.requested_by  IS DISTINCT FROM OLD.requested_by  THEN RAISE EXCEPTION 'export_jobs.requested_by is immutable'  USING ERRCODE = 'insufficient_privilege'; END IF;
    IF NEW.requested_at  IS DISTINCT FROM OLD.requested_at  THEN RAISE EXCEPTION 'export_jobs.requested_at is immutable'  USING ERRCODE = 'insufficient_privilege'; END IF;
    IF NEW.filters       IS DISTINCT FROM OLD.filters       THEN RAISE EXCEPTION 'export_jobs.filters is immutable'       USING ERRCODE = 'insufficient_privilege'; END IF;
    IF NEW.format        IS DISTINCT FROM OLD.format        THEN RAISE EXCEPTION 'export_jobs.format is immutable'        USING ERRCODE = 'insufficient_privilege'; END IF;
    IF NEW.encrypt_gpg   IS DISTINCT FROM OLD.encrypt_gpg   THEN RAISE EXCEPTION 'export_jobs.encrypt_gpg is immutable'   USING ERRCODE = 'insufficient_privilege'; END IF;
    IF NEW.gpg_recipient IS DISTINCT FROM OLD.gpg_recipient THEN RAISE EXCEPTION 'export_jobs.gpg_recipient is immutable' USING ERRCODE = 'insufficient_privilege'; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS export_jobs_immutable_cols ON audit.export_jobs;
CREATE TRIGGER export_jobs_immutable_cols
    BEFORE UPDATE ON audit.export_jobs
    FOR EACH ROW EXECUTE FUNCTION audit.export_jobs_restrict();

-- DELETE on export_jobs left open: legitimate retention sweep after
-- artifact expiry. The deletion ITSELF is audit.export.expired in
-- the main audit_log.

COMMIT;
