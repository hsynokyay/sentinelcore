CREATE OR REPLACE FUNCTION findings.prevent_core_field_update()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.title IS DISTINCT FROM NEW.title
       OR OLD.description IS DISTINCT FROM NEW.description
       OR OLD.severity IS DISTINCT FROM NEW.severity
       OR OLD.cwe_id IS DISTINCT FROM NEW.cwe_id
       OR OLD.file_path IS DISTINCT FROM NEW.file_path
       OR OLD.url IS DISTINCT FROM NEW.url
       OR OLD.code_snippet IS DISTINCT FROM NEW.code_snippet
       OR OLD.evidence_ref IS DISTINCT FROM NEW.evidence_ref
       OR OLD.evidence_hash IS DISTINCT FROM NEW.evidence_hash
       OR OLD.fingerprint IS DISTINCT FROM NEW.fingerprint
       OR OLD.finding_type IS DISTINCT FROM NEW.finding_type
       OR OLD.scan_job_id IS DISTINCT FROM NEW.scan_job_id
    THEN
        RAISE EXCEPTION 'Cannot modify immutable finding fields';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER findings_immutability
    BEFORE UPDATE ON findings.findings
    FOR EACH ROW EXECUTE FUNCTION findings.prevent_core_field_update();
