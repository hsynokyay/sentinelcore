-- Backfill rule_id for DAST findings based on CWE + title patterns.
-- This maps existing seeded DAST findings to the new DAST remediation packs.

UPDATE findings.findings SET rule_id = 'SC-DAST-CSRF-001'
 WHERE finding_type = 'dast' AND cwe_id = 352 AND rule_id IS NULL;

UPDATE findings.findings SET rule_id = 'SC-DAST-MIXED-001'
 WHERE finding_type = 'dast' AND cwe_id = 319 AND rule_id IS NULL;

UPDATE findings.findings SET rule_id = 'SC-DAST-AUTOCOMPLETE-001'
 WHERE finding_type = 'dast' AND cwe_id = 522 AND rule_id IS NULL;

UPDATE findings.findings SET rule_id = 'SC-DAST-INLINE-001'
 WHERE finding_type = 'dast' AND cwe_id = 829 AND rule_id IS NULL;

UPDATE findings.findings SET rule_id = 'SC-DAST-AUTHZ-001'
 WHERE finding_type = 'dast' AND cwe_id = 284 AND rule_id IS NULL;

UPDATE findings.findings SET rule_id = 'SC-DAST-XSS-001'
 WHERE finding_type = 'dast' AND cwe_id = 79 AND rule_id IS NULL;

UPDATE findings.findings SET rule_id = 'SC-DAST-SSRF-001'
 WHERE finding_type = 'dast' AND cwe_id = 918 AND rule_id IS NULL;

UPDATE findings.findings SET rule_id = 'SC-DAST-OPENREDIRECT-001'
 WHERE finding_type = 'dast' AND cwe_id = 601 AND rule_id IS NULL;

-- Security headers: CWE-693 (CSP), CWE-523 (HSTS), CWE-1021 (X-Frame-Options),
-- CWE-16 (X-Content-Type-Options), CWE-200 (Referrer-Policy)
UPDATE findings.findings SET rule_id = 'SC-DAST-SECHEADERS-001'
 WHERE finding_type = 'dast' AND cwe_id IN (693, 523, 1021, 16, 200)
   AND title LIKE 'Missing%header%' AND rule_id IS NULL;

UPDATE findings.findings SET rule_id = 'SC-DAST-COOKIEFLAGS-001'
 WHERE finding_type = 'dast' AND cwe_id = 614 AND rule_id IS NULL;

-- Additional DAST findings that map to existing SAST-like rule classes:
UPDATE findings.findings SET rule_id = 'SC-DAST-XSS-001'
 WHERE finding_type = 'dast' AND title LIKE '%XSS%' AND rule_id IS NULL;

UPDATE findings.findings SET rule_id = 'SC-DAST-SSRF-001'
 WHERE finding_type = 'dast' AND title LIKE '%SSRF%' AND rule_id IS NULL;
