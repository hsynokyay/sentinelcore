DROP TRIGGER IF EXISTS findings_immutability ON findings.findings;
DROP FUNCTION IF EXISTS findings.prevent_core_field_update();
