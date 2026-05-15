-- migrations/025_compliance_seed.up.sql
-- Phase 5: built-in compliance catalogs + CWE→control mappings.
--
-- Seeds three normative catalogs (OWASP Top 10 2021, PCI DSS 4.0,
-- NIST 800-53 R5) plus the canonical control items inside each, then
-- populates governance.control_mappings with the CWE→control links the
-- compliance.ResolveControls resolver depends on.
--
-- All inserts use ON CONFLICT DO NOTHING so the migration is idempotent
-- and safe to re-run.

-- ---------------------------------------------------------------------
-- §1 Catalogs
-- ---------------------------------------------------------------------

INSERT INTO governance.control_catalogs (org_id, code, name, version, description, is_builtin)
VALUES
    (NULL, 'OWASP_TOP10_2021', 'OWASP Top 10 (2021)', '2021',
     'OWASP Top 10 web application security risks, 2021 edition.', true),
    (NULL, 'PCI_DSS_4_0', 'PCI DSS', '4.0',
     'Payment Card Industry Data Security Standard v4.0.', true),
    (NULL, 'NIST_800_53_R5', 'NIST SP 800-53', 'Rev. 5',
     'NIST Special Publication 800-53 Revision 5 security controls.', true)
ON CONFLICT (org_id, code, version) DO NOTHING;

-- ---------------------------------------------------------------------
-- §2 OWASP Top 10 (2021) items — A01..A10
-- ---------------------------------------------------------------------

INSERT INTO governance.control_items (catalog_id, control_id, title, description)
SELECT c.id, v.cid, v.title, v.descr
FROM governance.control_catalogs c
CROSS JOIN (VALUES
    ('A01', 'Broken Access Control', 'Access control enforcement failures including IDOR, missing authz, and privilege escalation.'),
    ('A02', 'Cryptographic Failures', 'Weak crypto, predictable secrets, missing TLS, plaintext sensitive data.'),
    ('A03', 'Injection', 'SQL/NoSQL/OS/LDAP/XSS injection via untrusted input flowing into interpreters.'),
    ('A04', 'Insecure Design', 'Threat modeling and secure-by-design failures, e.g. missing rate limiting.'),
    ('A05', 'Security Misconfiguration', 'Default credentials, verbose errors, missing hardening, open S3/GCS buckets.'),
    ('A06', 'Vulnerable and Outdated Components', 'Known-vulnerable libraries / outdated runtimes / missing updates.'),
    ('A07', 'Identification and Authentication Failures', 'Weak auth, credential stuffing, session fixation, missing MFA.'),
    ('A08', 'Software and Data Integrity Failures', 'Insecure deserialization, unsigned updates, untrusted CI/CD pipelines.'),
    ('A09', 'Security Logging and Monitoring Failures', 'Missing audit trails, log injection, undetected breaches.'),
    ('A10', 'Server-Side Request Forgery', 'SSRF — server makes attacker-controlled outbound requests to internal targets.')
) AS v(cid, title, descr)
WHERE c.code = 'OWASP_TOP10_2021' AND c.org_id IS NULL
ON CONFLICT (catalog_id, control_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- §3 PCI DSS 4.0 items (subset that maps from common CWEs)
-- ---------------------------------------------------------------------

INSERT INTO governance.control_items (catalog_id, control_id, title, description)
SELECT c.id, v.cid, v.title, v.descr
FROM governance.control_catalogs c
CROSS JOIN (VALUES
    ('3.5.1', 'Render PAN unreadable', 'Strong cryptography for stored cardholder data.'),
    ('4.2.1', 'Strong cryptography for transmissions', 'Encrypt cardholder data over public networks.'),
    ('6.2.4', 'Secure coding — injection', 'Software engineered to prevent injection attacks.'),
    ('6.2.5', 'Secure coding — auth/session', 'Software engineered to prevent broken auth/session.'),
    ('6.2.6', 'Secure coding — access control', 'Software engineered to prevent insecure access.'),
    ('6.4.1', 'Public-facing web app review', 'Public-facing web applications reviewed for vulnerabilities.'),
    ('7.2.1', 'Access control system in place', 'Restrict access to system components.'),
    ('8.3.1', 'MFA for all non-console admin access', 'Multi-factor auth for cardholder data environment.'),
    ('10.2.1', 'Audit logs of user activity', 'Log all individual user accesses to cardholder data.'),
    ('11.3.1', 'Internal vulnerability scans', 'Vulnerability scans run at least every three months.'),
    ('11.4.1', 'External penetration testing', 'External pen tests at least annually.'),
    ('12.10.1', 'Incident response plan', 'Documented incident response plan ready for activation.')
) AS v(cid, title, descr)
WHERE c.code = 'PCI_DSS_4_0' AND c.org_id IS NULL
ON CONFLICT (catalog_id, control_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- §4 NIST 800-53 R5 items (subset)
-- ---------------------------------------------------------------------

INSERT INTO governance.control_items (catalog_id, control_id, title, description)
SELECT c.id, v.cid, v.title, v.descr
FROM governance.control_catalogs c
CROSS JOIN (VALUES
    ('AC-3', 'Access Enforcement', 'Enforce approved authorizations for logical access.'),
    ('AC-4', 'Information Flow Enforcement', 'Control information flows within and between systems.'),
    ('AC-6', 'Least Privilege', 'Authorize access for minimum necessary actions.'),
    ('AC-7', 'Unsuccessful Logon Attempts', 'Lockout after consecutive invalid attempts.'),
    ('AU-2', 'Event Logging', 'Identify which events to log to support audit.'),
    ('AU-12', 'Audit Record Generation', 'Provide audit record generation capability.'),
    ('CM-7', 'Least Functionality', 'Configure systems to provide essential capabilities only.'),
    ('IA-2', 'Identification and Authentication', 'Uniquely identify and authenticate users.'),
    ('IA-5', 'Authenticator Management', 'Manage authenticators (passwords, tokens, certs).'),
    ('IA-8', 'Identification and Authentication (Non-Org Users)', 'Identify external users.'),
    ('RA-5', 'Vulnerability Monitoring and Scanning', 'Scan for vulnerabilities and remediate.'),
    ('SA-11', 'Developer Testing and Evaluation', 'Require developers to test and evaluate.'),
    ('SC-7', 'Boundary Protection', 'Monitor and control communications at boundaries.'),
    ('SC-8', 'Transmission Confidentiality and Integrity', 'Protect transmitted information.'),
    ('SC-12', 'Cryptographic Key Establishment', 'Establish/manage cryptographic keys.'),
    ('SC-13', 'Cryptographic Protection', 'Implement approved cryptographic mechanisms.'),
    ('SC-28', 'Protection of Information at Rest', 'Protect information at rest.'),
    ('SI-2', 'Flaw Remediation', 'Identify, report, and correct system flaws.'),
    ('SI-10', 'Information Input Validation', 'Validate information inputs to systems.'),
    ('SI-11', 'Error Handling', 'Generate error messages without revealing info.')
) AS v(cid, title, descr)
WHERE c.code = 'NIST_800_53_R5' AND c.org_id IS NULL
ON CONFLICT (catalog_id, control_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- §5 CWE → OWASP Top 10 (2021) mappings
-- ---------------------------------------------------------------------

WITH m(cwe, control) AS (VALUES
    -- A01 Broken Access Control
    ('CWE-22','A01'),('CWE-23','A01'),('CWE-200','A01'),('CWE-201','A01'),
    ('CWE-284','A01'),('CWE-285','A01'),('CWE-352','A01'),('CWE-425','A01'),
    ('CWE-639','A01'),
    -- A02 Cryptographic Failures
    ('CWE-261','A02'),('CWE-295','A02'),('CWE-310','A02'),('CWE-319','A02'),
    ('CWE-321','A02'),('CWE-326','A02'),('CWE-327','A02'),('CWE-328','A02'),
    ('CWE-330','A02'),('CWE-759','A02'),('CWE-760','A02'),('CWE-798','A02'),
    -- A03 Injection
    ('CWE-20','A03'),('CWE-77','A03'),('CWE-78','A03'),('CWE-79','A03'),
    ('CWE-88','A03'),('CWE-89','A03'),('CWE-90','A03'),('CWE-91','A03'),
    ('CWE-94','A03'),('CWE-113','A03'),('CWE-184','A03'),('CWE-643','A03'),
    -- A04 Insecure Design
    ('CWE-209','A04'),('CWE-256','A04'),('CWE-501','A04'),('CWE-522','A04'),
    ('CWE-601','A04'),('CWE-770','A04'),
    -- A05 Security Misconfiguration
    ('CWE-2','A05'),('CWE-11','A05'),('CWE-13','A05'),('CWE-15','A05'),
    ('CWE-16','A05'),('CWE-260','A05'),('CWE-315','A05'),('CWE-520','A05'),
    ('CWE-1004','A05'),
    -- A06 Vulnerable and Outdated Components
    ('CWE-937','A06'),('CWE-1035','A06'),('CWE-1104','A06'),
    -- A07 Identification and Authentication Failures
    ('CWE-255','A07'),('CWE-259','A07'),('CWE-287','A07'),('CWE-288','A07'),
    ('CWE-290','A07'),('CWE-294','A07'),('CWE-297','A07'),('CWE-300','A07'),
    ('CWE-306','A07'),('CWE-307','A07'),('CWE-384','A07'),('CWE-521','A07'),
    -- A08 Software and Data Integrity Failures
    ('CWE-345','A08'),('CWE-353','A08'),('CWE-426','A08'),('CWE-494','A08'),
    ('CWE-502','A08'),('CWE-565','A08'),('CWE-784','A08'),('CWE-829','A08'),
    -- A09 Security Logging and Monitoring Failures
    ('CWE-117','A09'),('CWE-223','A09'),('CWE-532','A09'),('CWE-778','A09'),
    -- A10 SSRF
    ('CWE-918','A10')
)
INSERT INTO governance.control_mappings
    (org_id, source_kind, source_code, target_control_id, confidence, source_version)
SELECT NULL, 'cwe', m.cwe, i.id, 'normative', 'OWASP Top 10 2021'
FROM m
JOIN governance.control_catalogs c ON c.code = 'OWASP_TOP10_2021' AND c.org_id IS NULL
JOIN governance.control_items   i ON i.catalog_id = c.id AND i.control_id = m.control
ON CONFLICT (org_id, source_kind, source_code, target_control_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- §6 CWE → PCI DSS 4.0 mappings
-- ---------------------------------------------------------------------

WITH m(cwe, control) AS (VALUES
    -- Injection-class → 6.2.4
    ('CWE-20','6.2.4'),('CWE-78','6.2.4'),('CWE-79','6.2.4'),('CWE-89','6.2.4'),
    ('CWE-94','6.2.4'),('CWE-77','6.2.4'),('CWE-90','6.2.4'),('CWE-643','6.2.4'),
    -- Auth/session → 6.2.5 + 8.3.1
    ('CWE-287','6.2.5'),('CWE-307','6.2.5'),('CWE-384','6.2.5'),('CWE-521','6.2.5'),
    ('CWE-306','8.3.1'),
    -- Access control → 6.2.6 + 7.2.1
    ('CWE-22','6.2.6'),('CWE-200','6.2.6'),('CWE-285','6.2.6'),('CWE-639','6.2.6'),
    ('CWE-284','7.2.1'),
    -- Crypto → 3.5.1 (at-rest) and 4.2.1 (in-transit)
    ('CWE-326','3.5.1'),('CWE-327','3.5.1'),('CWE-328','3.5.1'),
    ('CWE-319','4.2.1'),('CWE-295','4.2.1'),
    -- Logging → 10.2.1
    ('CWE-117','10.2.1'),('CWE-532','10.2.1'),('CWE-778','10.2.1')
)
INSERT INTO governance.control_mappings
    (org_id, source_kind, source_code, target_control_id, confidence, source_version)
SELECT NULL, 'cwe', m.cwe, i.id, 'normative', 'PCI DSS 4.0'
FROM m
JOIN governance.control_catalogs c ON c.code = 'PCI_DSS_4_0' AND c.org_id IS NULL
JOIN governance.control_items   i ON i.catalog_id = c.id AND i.control_id = m.control
ON CONFLICT (org_id, source_kind, source_code, target_control_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- §7 CWE → NIST 800-53 R5 mappings
-- ---------------------------------------------------------------------

WITH m(cwe, control) AS (VALUES
    -- Access control / authz
    ('CWE-22','AC-3'),('CWE-200','AC-3'),('CWE-284','AC-3'),('CWE-285','AC-3'),
    ('CWE-639','AC-3'),
    -- Least privilege
    ('CWE-250','AC-6'),('CWE-269','AC-6'),
    -- Authentication
    ('CWE-287','IA-2'),('CWE-306','IA-2'),('CWE-384','IA-2'),
    ('CWE-307','AC-7'),
    ('CWE-259','IA-5'),('CWE-521','IA-5'),('CWE-798','IA-5'),
    -- Crypto
    ('CWE-327','SC-13'),('CWE-326','SC-13'),('CWE-328','SC-13'),
    ('CWE-319','SC-8'),('CWE-295','SC-8'),
    ('CWE-321','SC-12'),
    ('CWE-311','SC-28'),('CWE-312','SC-28'),
    -- Boundary / SSRF
    ('CWE-918','SC-7'),('CWE-601','SC-7'),
    -- Input validation / injection
    ('CWE-20','SI-10'),('CWE-79','SI-10'),('CWE-89','SI-10'),('CWE-78','SI-10'),
    ('CWE-94','SI-10'),
    -- Error handling / info exposure
    ('CWE-209','SI-11'),
    -- Logging
    ('CWE-117','AU-2'),('CWE-532','AU-12'),('CWE-778','AU-12'),
    -- Vulnerable components / patching
    ('CWE-937','SI-2'),('CWE-1104','RA-5')
)
INSERT INTO governance.control_mappings
    (org_id, source_kind, source_code, target_control_id, confidence, source_version)
SELECT NULL, 'cwe', m.cwe, i.id, 'normative', 'NIST SP 800-53 Rev. 5'
FROM m
JOIN governance.control_catalogs c ON c.code = 'NIST_800_53_R5' AND c.org_id IS NULL
JOIN governance.control_items   i ON i.catalog_id = c.id AND i.control_id = m.control
ON CONFLICT (org_id, source_kind, source_code, target_control_id) DO NOTHING;
