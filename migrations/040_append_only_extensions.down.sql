BEGIN;
DROP TRIGGER IF EXISTS export_jobs_immutable_cols      ON audit.export_jobs;
DROP FUNCTION IF EXISTS audit.export_jobs_restrict();
DROP TRIGGER IF EXISTS state_transitions_no_delete     ON findings.finding_state_transitions;
DROP TRIGGER IF EXISTS state_transitions_no_update     ON findings.finding_state_transitions;
COMMIT;
