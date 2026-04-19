-- Add rule_id to findings for remediation pack lookup.
ALTER TABLE findings.findings ADD COLUMN IF NOT EXISTS rule_id TEXT;

-- Backfill existing SAST findings from the current scan.
UPDATE findings.findings SET rule_id = 'SC-JAVA-SQL-001' WHERE cwe_id = 89 AND finding_type IN ('sast') AND rule_id IS NULL;
UPDATE findings.findings SET rule_id = 'SC-JAVA-CMD-001' WHERE cwe_id = 78 AND finding_type IN ('sast') AND rule_id IS NULL;
UPDATE findings.findings SET rule_id = 'SC-JAVA-PATH-001' WHERE cwe_id = 22 AND finding_type IN ('sast') AND rule_id IS NULL;
UPDATE findings.findings SET rule_id = 'SC-JAVA-CRYPTO-001' WHERE cwe_id IN (327, 328) AND finding_type IN ('sast') AND rule_id IS NULL;
UPDATE findings.findings SET rule_id = 'SC-JAVA-SECRET-001' WHERE cwe_id IN (798, 259) AND finding_type IN ('sast', 'secret') AND rule_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings.findings(rule_id) WHERE rule_id IS NOT NULL;
