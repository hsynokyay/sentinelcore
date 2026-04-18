BEGIN;

DROP TRIGGER IF EXISTS integrity_checks_no_update ON audit.integrity_checks;
DROP TRIGGER IF EXISTS integrity_checks_no_delete ON audit.integrity_checks;
DROP TABLE IF EXISTS audit.integrity_checks;

DROP TABLE IF EXISTS audit.hmac_keys;

DROP INDEX IF EXISTS audit.audit_log_event_id_uniq;

DROP TRIGGER IF EXISTS audit_log_no_delete ON audit.audit_log;
DROP TRIGGER IF EXISTS audit_log_no_update ON audit.audit_log;
DROP FUNCTION IF EXISTS audit.prevent_mutation();

COMMIT;
