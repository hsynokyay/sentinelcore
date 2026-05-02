-- Revert: clear DAST rule_ids.
UPDATE findings.findings SET rule_id = NULL WHERE rule_id LIKE 'SC-DAST-%';
