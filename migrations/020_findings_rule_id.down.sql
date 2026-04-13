DROP INDEX IF EXISTS findings.idx_findings_rule_id;
ALTER TABLE findings.findings DROP COLUMN IF EXISTS rule_id;
