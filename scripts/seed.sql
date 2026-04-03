-- =============================================================================
-- SentinelCore Demo Seed Data
-- Idempotent: uses INSERT ... ON CONFLICT DO NOTHING throughout
-- Run: psql -f scripts/seed.sql
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Organization
-- ---------------------------------------------------------------------------
INSERT INTO core.organizations (id, name, display_name, settings)
VALUES (
    '11111111-1111-1111-1111-111111111111',
    'sentinelcore-demo',
    'SentinelCore Demo',
    '{"sso_enabled": false, "mfa_required": false}'::jsonb
) ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. Teams
-- ---------------------------------------------------------------------------
INSERT INTO core.teams (id, org_id, name, display_name) VALUES
    ('22222222-2222-2222-2222-222222222201', '11111111-1111-1111-1111-111111111111', 'platform-security', 'Platform Security'),
    ('22222222-2222-2222-2222-222222222202', '11111111-1111-1111-1111-111111111111', 'application-security', 'Application Security')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 3. Users (password: SentinelDemo1!)
-- ---------------------------------------------------------------------------
INSERT INTO core.users (id, org_id, username, email, display_name, password_hash, role, status) VALUES
    ('33333333-3333-3333-3333-333333333301', '11111111-1111-1111-1111-111111111111',
     'admin', 'admin@sentinel.io', 'Admin User',
     '$2a$10$rKN7MIlxFfXHVfmJxRLZz.8sSZxcXHMvL.5Jq1kFhGHqJx1TzV2Ky',
     'platform_admin', 'active'),
    ('33333333-3333-3333-3333-333333333302', '11111111-1111-1111-1111-111111111111',
     'secadmin', 'secadmin@sentinel.io', 'Security Admin',
     '$2a$10$rKN7MIlxFfXHVfmJxRLZz.8sSZxcXHMvL.5Jq1kFhGHqJx1TzV2Ky',
     'security_admin', 'active'),
    ('33333333-3333-3333-3333-333333333303', '11111111-1111-1111-1111-111111111111',
     'analyst', 'analyst@sentinel.io', 'AppSec Analyst',
     '$2a$10$rKN7MIlxFfXHVfmJxRLZz.8sSZxcXHMvL.5Jq1kFhGHqJx1TzV2Ky',
     'appsec_analyst', 'active'),
    ('33333333-3333-3333-3333-333333333304', '11111111-1111-1111-1111-111111111111',
     'auditor', 'auditor@sentinel.io', 'Compliance Auditor',
     '$2a$10$rKN7MIlxFfXHVfmJxRLZz.8sSZxcXHMvL.5Jq1kFhGHqJx1TzV2Ky',
     'auditor', 'active')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 4. Team memberships (all users in both teams)
-- ---------------------------------------------------------------------------
INSERT INTO core.team_memberships (team_id, user_id, role, granted_by) VALUES
    -- platform-security team
    ('22222222-2222-2222-2222-222222222201', '33333333-3333-3333-3333-333333333301', 'team_admin', '33333333-3333-3333-3333-333333333301'),
    ('22222222-2222-2222-2222-222222222201', '33333333-3333-3333-3333-333333333302', 'analyst',    '33333333-3333-3333-3333-333333333301'),
    ('22222222-2222-2222-2222-222222222201', '33333333-3333-3333-3333-333333333303', 'analyst',    '33333333-3333-3333-3333-333333333301'),
    ('22222222-2222-2222-2222-222222222201', '33333333-3333-3333-3333-333333333304', 'analyst',    '33333333-3333-3333-3333-333333333301'),
    -- application-security team
    ('22222222-2222-2222-2222-222222222202', '33333333-3333-3333-3333-333333333301', 'team_admin', '33333333-3333-3333-3333-333333333301'),
    ('22222222-2222-2222-2222-222222222202', '33333333-3333-3333-3333-333333333302', 'analyst',    '33333333-3333-3333-3333-333333333301'),
    ('22222222-2222-2222-2222-222222222202', '33333333-3333-3333-3333-333333333303', 'analyst',    '33333333-3333-3333-3333-333333333301'),
    ('22222222-2222-2222-2222-222222222202', '33333333-3333-3333-3333-333333333304', 'analyst',    '33333333-3333-3333-3333-333333333301')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 5. Projects
-- ---------------------------------------------------------------------------
INSERT INTO core.projects (id, org_id, team_id, name, display_name, description, repository_url, asset_criticality, tags) VALUES
    ('44444444-4444-4444-4444-444444444401', '11111111-1111-1111-1111-111111111111',
     '22222222-2222-2222-2222-222222222201',
     'web-application', 'Web Application', 'Main customer-facing web application',
     'https://github.com/sentinelcore/web-app', 'critical', '{frontend, production}'),
    ('44444444-4444-4444-4444-444444444402', '11111111-1111-1111-1111-111111111111',
     '22222222-2222-2222-2222-222222222202',
     'api-service', 'API Service', 'Backend REST API service',
     'https://github.com/sentinelcore/api-service', 'high', '{backend, api, production}')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 6. Scan targets
-- ---------------------------------------------------------------------------
INSERT INTO core.scan_targets (id, project_id, target_type, base_url, allowed_domains, max_rps,
                               verified_at, verified_by) VALUES
    ('55555555-5555-5555-5555-555555555501', '44444444-4444-4444-4444-444444444401',
     'web_app', 'https://demo.sentinelcore.io', '{demo.sentinelcore.io}', 20,
     now() - interval '30 days', '33333333-3333-3333-3333-333333333301'),
    ('55555555-5555-5555-5555-555555555502', '44444444-4444-4444-4444-444444444402',
     'api', 'https://api.sentinelcore.io', '{api.sentinelcore.io}', 15,
     now() - interval '30 days', '33333333-3333-3333-3333-333333333301')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 7. Scan jobs (3 completed scans)
-- ---------------------------------------------------------------------------
INSERT INTO scans.scan_jobs (id, project_id, scan_type, scan_profile, status, trigger_type,
                             scan_target_id, worker_id, started_at, completed_at, created_by,
                             progress) VALUES
    -- SAST on web-application
    ('66666666-6666-6666-6666-666666666601', '44444444-4444-4444-4444-444444444401',
     'sast', 'standard', 'completed', 'manual',
     '55555555-5555-5555-5555-555555555501', 'worker-01',
     now() - interval '7 days', now() - interval '7 days' + interval '42 minutes',
     '33333333-3333-3333-3333-333333333302',
     '{"phase": "completed", "percent": 100}'::jsonb),
    -- DAST on api-service
    ('66666666-6666-6666-6666-666666666602', '44444444-4444-4444-4444-444444444402',
     'dast', 'standard', 'completed', 'scheduled',
     '55555555-5555-5555-5555-555555555502', 'worker-02',
     now() - interval '5 days', now() - interval '5 days' + interval '1 hour 18 minutes',
     '33333333-3333-3333-3333-333333333302',
     '{"phase": "completed", "percent": 100}'::jsonb),
    -- DAST on web-application
    ('66666666-6666-6666-6666-666666666603', '44444444-4444-4444-4444-444444444401',
     'dast', 'aggressive', 'completed', 'manual',
     '55555555-5555-5555-5555-555555555501', 'worker-01',
     now() - interval '3 days', now() - interval '3 days' + interval '55 minutes',
     '33333333-3333-3333-3333-333333333301',
     '{"phase": "completed", "percent": 100}'::jsonb)
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 8. Findings (25 total)
-- ---------------------------------------------------------------------------

-- === CRITICAL (3) ===
INSERT INTO findings.findings (id, project_id, scan_job_id, finding_type, fingerprint, title, description, cwe_id, owasp_category, severity, confidence, cvss_score, cvss_vector, file_path, line_start, code_snippet, url, http_method, parameter, status, risk_score, org_id, assigned_to, sla_deadline) VALUES
    -- SQL Injection (SAST)
    ('77777777-7777-7777-7777-777777770101', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666601', 'sast',
     'fp-sqli-usercontroller-42', 'SQL Injection in UserController.getUser()',
     'User-controlled input is concatenated directly into a SQL query in UserController.java line 42. An attacker can manipulate the id parameter to extract arbitrary data from the database, modify records, or execute administrative operations.',
     89, 'A03:2021-Injection', 'critical', 'high', 9.8,
     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
     'src/main/java/io/sentinel/controller/UserController.java', 42,
     'String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");',
     NULL, NULL, 'id',
     'confirmed', 98.50,
     '11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333303',
     now() + interval '3 days'),
    -- Remote Code Execution (DAST)
    ('77777777-7777-7777-7777-777777770102', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-rce-api-exec-endpoint', 'Remote Code Execution via /api/v1/exec endpoint',
     'The /api/v1/exec endpoint accepts a command parameter that is passed to a system shell without sanitization. An unauthenticated attacker can execute arbitrary OS commands on the server.',
     78, 'A03:2021-Injection', 'critical', 'high', 10.0,
     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
     NULL, NULL, NULL,
     'https://api.sentinelcore.io/api/v1/exec', 'POST', 'command',
     'in_progress', 99.00,
     '11111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333302',
     now() + interval '2 days'),
    -- Hardcoded Secrets
    ('77777777-7777-7777-7777-777777770103', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666601', 'secret',
     'fp-secret-dbconfig-aws', 'Hardcoded AWS Access Key in DatabaseConfig.java',
     'An AWS access key ID and secret key are hardcoded in the database configuration file. These credentials grant access to production S3 buckets and RDS instances.',
     798, 'A02:2021-Cryptographic Failures', 'critical', 'high', 9.1,
     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
     'src/main/resources/DatabaseConfig.java', 18,
     'private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";',
     NULL, NULL, NULL,
     'new', 96.00,
     '11111111-1111-1111-1111-111111111111', NULL,
     now() + interval '3 days')
ON CONFLICT DO NOTHING;

-- === HIGH (5) ===
INSERT INTO findings.findings (id, project_id, scan_job_id, finding_type, fingerprint, title, description, cwe_id, owasp_category, severity, confidence, cvss_score, file_path, line_start, url, http_method, parameter, status, risk_score, org_id) VALUES
    -- XSS Reflected
    ('77777777-7777-7777-7777-777777770201', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-xss-search-q', 'Reflected XSS in /search via q parameter',
     'The search page reflects the q query parameter in the HTML response without encoding. An attacker can craft a URL that executes JavaScript in the context of the victim''s browser session.',
     79, 'A03:2021-Injection', 'high', 'high', 8.2,
     NULL, NULL,
     'https://demo.sentinelcore.io/search', 'GET', 'q',
     'confirmed', 82.00, '11111111-1111-1111-1111-111111111111'),
    -- SSRF
    ('77777777-7777-7777-7777-777777770202', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-ssrf-webhook-url', 'Server-Side Request Forgery in webhook configuration',
     'The webhook registration endpoint allows specifying arbitrary URLs. An attacker can use this to scan internal networks, access cloud metadata endpoints (169.254.169.254), and exfiltrate data.',
     918, 'A10:2021-SSRF', 'high', 'medium', 7.5,
     NULL, NULL,
     'https://api.sentinelcore.io/api/v1/webhooks', 'POST', 'callback_url',
     'in_progress', 78.00, '11111111-1111-1111-1111-111111111111'),
    -- Path Traversal
    ('77777777-7777-7777-7777-777777770203', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-pathtraversal-download', 'Path Traversal in file download endpoint',
     'The /api/download endpoint accepts a filename parameter vulnerable to directory traversal. Payloads like ../../etc/passwd allow reading arbitrary files from the server.',
     22, 'A01:2021-Broken Access Control', 'high', 'high', 7.5,
     NULL, NULL,
     'https://demo.sentinelcore.io/api/download', 'GET', 'filename',
     'resolved', 75.00, '11111111-1111-1111-1111-111111111111'),
    -- Insecure Deserialization
    ('77777777-7777-7777-7777-777777770204', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-deser-session-cookie', 'Insecure Deserialization in session cookie',
     'The application uses Java serialization for session tokens. An attacker can craft a malicious serialized object to achieve remote code execution when the server deserializes the cookie.',
     502, 'A08:2021-Software and Data Integrity', 'high', 'medium', 8.1,
     NULL, NULL,
     'https://api.sentinelcore.io/api/v1/session', 'POST', 'session_token',
     'new', 80.00, '11111111-1111-1111-1111-111111111111'),
    -- Broken Authentication
    ('77777777-7777-7777-7777-777777770205', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-brokenauth-ratelimit', 'Missing rate limiting on authentication endpoint',
     'The /auth/login endpoint does not enforce rate limiting or account lockout. An attacker can perform unlimited brute-force attempts against user credentials.',
     307, 'A07:2021-Identification and Authentication Failures', 'high', 'high', 7.4,
     NULL, NULL,
     'https://demo.sentinelcore.io/auth/login', 'POST', NULL,
     'confirmed', 74.00, '11111111-1111-1111-1111-111111111111')
ON CONFLICT DO NOTHING;

-- === MEDIUM (8) ===
INSERT INTO findings.findings (id, project_id, scan_job_id, finding_type, fingerprint, title, description, cwe_id, owasp_category, severity, confidence, cvss_score, url, http_method, file_path, line_start, status, risk_score, org_id) VALUES
    -- CSRF
    ('77777777-7777-7777-7777-777777770301', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-csrf-settings-form', 'Missing CSRF token on account settings form',
     'The account settings form does not include a CSRF token. An attacker can host a malicious page that submits a forged request to change the victim''s email or password.',
     352, 'A01:2021-Broken Access Control', 'medium', 'high', 6.5,
     'https://demo.sentinelcore.io/settings', 'POST', NULL, NULL,
     'in_progress', 55.00, '11111111-1111-1111-1111-111111111111'),
    -- Mixed Content
    ('77777777-7777-7777-7777-777777770302', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-mixedcontent-cdn', 'Mixed content loading scripts over HTTP',
     'The page loads JavaScript files from an HTTP CDN endpoint. This allows a man-in-the-middle attacker to inject malicious code into the page.',
     319, 'A02:2021-Cryptographic Failures', 'medium', 'high', 5.9,
     'https://demo.sentinelcore.io/dashboard', 'GET', NULL, NULL,
     'confirmed', 50.00, '11111111-1111-1111-1111-111111111111'),
    -- Open Redirect
    ('77777777-7777-7777-7777-777777770303', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-openredirect-login', 'Open redirect via return_url parameter on login',
     'The login page accepts a return_url parameter that redirects to any external domain. An attacker can craft phishing URLs that appear to originate from the legitimate application.',
     601, 'A01:2021-Broken Access Control', 'medium', 'medium', 4.7,
     'https://demo.sentinelcore.io/auth/login', 'GET', NULL, NULL,
     'new', 40.00, '11111111-1111-1111-1111-111111111111'),
    -- Missing Security Headers (5 findings)
    ('77777777-7777-7777-7777-777777770304', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-header-csp-missing', 'Missing Content-Security-Policy header',
     'The application does not set a Content-Security-Policy header, allowing inline scripts and loading resources from any origin.',
     693, 'A05:2021-Security Misconfiguration', 'medium', 'high', 5.3,
     'https://demo.sentinelcore.io/', 'GET', NULL, NULL,
     'new', 42.00, '11111111-1111-1111-1111-111111111111'),
    ('77777777-7777-7777-7777-777777770305', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-header-hsts-missing', 'Missing Strict-Transport-Security header',
     'The API does not set HSTS headers, allowing downgrade attacks from HTTPS to HTTP.',
     523, 'A05:2021-Security Misconfiguration', 'medium', 'high', 5.3,
     'https://api.sentinelcore.io/', 'GET', NULL, NULL,
     'new', 42.00, '11111111-1111-1111-1111-111111111111'),
    ('77777777-7777-7777-7777-777777770306', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-header-xframe-missing', 'Missing X-Frame-Options header',
     'The application can be framed by external sites, enabling clickjacking attacks.',
     1021, 'A05:2021-Security Misconfiguration', 'medium', 'high', 4.3,
     'https://demo.sentinelcore.io/', 'GET', NULL, NULL,
     'confirmed', 38.00, '11111111-1111-1111-1111-111111111111'),
    ('77777777-7777-7777-7777-777777770307', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-header-xcontent-missing', 'Missing X-Content-Type-Options header',
     'The API responses lack the X-Content-Type-Options: nosniff header, enabling MIME type sniffing attacks.',
     16, 'A05:2021-Security Misconfiguration', 'medium', 'medium', 4.3,
     'https://api.sentinelcore.io/', 'GET', NULL, NULL,
     'new', 36.00, '11111111-1111-1111-1111-111111111111'),
    ('77777777-7777-7777-7777-777777770308', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-header-referrer-missing', 'Missing Referrer-Policy header',
     'The application does not set a Referrer-Policy header. Full referrer URLs including query parameters may be leaked to third-party sites.',
     200, 'A05:2021-Security Misconfiguration', 'medium', 'medium', 3.7,
     'https://demo.sentinelcore.io/', 'GET', NULL, NULL,
     'new', 32.00, '11111111-1111-1111-1111-111111111111')
ON CONFLICT DO NOTHING;

-- === LOW (6) ===
INSERT INTO findings.findings (id, project_id, scan_job_id, finding_type, fingerprint, title, description, cwe_id, owasp_category, severity, confidence, cvss_score, url, http_method, file_path, line_start, parameter, status, risk_score, org_id) VALUES
    -- Autocomplete
    ('77777777-7777-7777-7777-777777770401', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-autocomplete-password', 'Password field has autocomplete enabled',
     'The password input field on the login form has autocomplete enabled. Browsers may store the password and offer to autofill it, which is a risk on shared workstations.',
     522, 'A04:2021-Insecure Design', 'low', 'high', 3.1,
     'https://demo.sentinelcore.io/auth/login', 'GET', NULL, NULL, 'password',
     'new', 18.00, '11111111-1111-1111-1111-111111111111'),
    -- Verbose Errors
    ('77777777-7777-7777-7777-777777770402', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-verbose-errors-stacktrace', 'Verbose error messages expose stack traces',
     'The API returns full Java stack traces in error responses. These traces reveal internal class names, library versions, and file paths that assist an attacker in targeting specific vulnerabilities.',
     209, 'A05:2021-Security Misconfiguration', 'low', 'high', 3.7,
     'https://api.sentinelcore.io/api/v1/users/invalid', 'GET', NULL, NULL, NULL,
     'confirmed', 22.00, '11111111-1111-1111-1111-111111111111'),
    -- Cookie Flags
    ('77777777-7777-7777-7777-777777770403', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-cookie-secure-missing', 'Session cookie missing Secure and SameSite flags',
     'The JSESSIONID cookie is set without the Secure flag or SameSite attribute. The cookie may be transmitted over unencrypted connections or included in cross-site requests.',
     614, 'A02:2021-Cryptographic Failures', 'low', 'high', 3.1,
     'https://demo.sentinelcore.io/', 'GET', NULL, NULL, NULL,
     'new', 20.00, '11111111-1111-1111-1111-111111111111'),
    -- Information Disclosure x3
    ('77777777-7777-7777-7777-777777770404', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-info-internal-ip', 'Internal IP address disclosed in response headers',
     'The X-Backend-Server response header reveals the internal IP address 10.0.4.17 of the application server, aiding network reconnaissance.',
     200, 'A01:2021-Broken Access Control', 'low', 'medium', 2.6,
     'https://api.sentinelcore.io/health', 'GET', NULL, NULL, NULL,
     'new', 15.00, '11111111-1111-1111-1111-111111111111'),
    ('77777777-7777-7777-7777-777777770405', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-info-email-disclosure', 'Email addresses disclosed in HTML comments',
     'HTML comments in the page source contain developer email addresses (dev-team@sentinelcore.io), providing targets for social engineering.',
     615, 'A01:2021-Broken Access Control', 'low', 'low', 2.1,
     'https://demo.sentinelcore.io/about', 'GET', NULL, NULL, NULL,
     'resolved', 12.00, '11111111-1111-1111-1111-111111111111'),
    ('77777777-7777-7777-7777-777777770406', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-info-directory-listing', 'Directory listing enabled on /static/',
     'The /static/ directory has directory listing enabled, exposing the file structure and potentially sensitive files.',
     548, 'A05:2021-Security Misconfiguration', 'low', 'high', 2.6,
     'https://api.sentinelcore.io/static/', 'GET', NULL, NULL, NULL,
     'new', 14.00, '11111111-1111-1111-1111-111111111111')
ON CONFLICT DO NOTHING;

-- === INFO (3) ===
INSERT INTO findings.findings (id, project_id, scan_job_id, finding_type, fingerprint, title, description, cwe_id, owasp_category, severity, confidence, url, http_method, status, risk_score, org_id) VALUES
    -- Software Version
    ('77777777-7777-7777-7777-777777770501', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-info-server-version', 'Web server version disclosed in Server header',
     'The Server response header reveals Apache/2.4.52 (Ubuntu). Knowing the exact server version helps attackers identify applicable CVEs.',
     200, 'A05:2021-Security Misconfiguration', 'info', 'high',
     'https://api.sentinelcore.io/', 'GET',
     'new', 8.00, '11111111-1111-1111-1111-111111111111'),
    -- Inline Scripts
    ('77777777-7777-7777-7777-777777770502', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'dast',
     'fp-info-inline-scripts', 'Multiple inline JavaScript blocks detected',
     'The page contains 12 inline script blocks. Inline scripts cannot be controlled by Content-Security-Policy nonce/hash directives without significant refactoring.',
     829, 'A05:2021-Security Misconfiguration', 'info', 'medium',
     'https://demo.sentinelcore.io/', 'GET',
     'new', 5.00, '11111111-1111-1111-1111-111111111111'),
    -- Debug Endpoints
    ('77777777-7777-7777-7777-777777770503', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'dast',
     'fp-info-debug-endpoint', 'Debug endpoint /debug/pprof accessible without authentication',
     'The Go pprof debug endpoint is accessible without authentication, leaking goroutine dumps, heap profiles, and other runtime internals.',
     215, 'A05:2021-Security Misconfiguration', 'info', 'high',
     'https://api.sentinelcore.io/debug/pprof/', 'GET',
     'confirmed', 10.00, '11111111-1111-1111-1111-111111111111')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 9. Finding state transitions (for findings not in "new" status)
-- ---------------------------------------------------------------------------
INSERT INTO findings.finding_state_transitions (id, finding_id, from_status, to_status, changed_by, reason, created_at) VALUES
    -- SQL Injection: new -> confirmed
    ('88888888-8888-8888-8888-888888880101', '77777777-7777-7777-7777-777777770101',
     'new', 'confirmed', '33333333-3333-3333-3333-333333333302',
     'Verified with manual testing; parameter injection confirmed via sqlmap', now() - interval '6 days'),
    -- RCE: new -> confirmed -> in_progress
    ('88888888-8888-8888-8888-888888880201', '77777777-7777-7777-7777-777777770102',
     'new', 'confirmed', '33333333-3333-3333-3333-333333333302',
     'Reproduced with curl; server executes arbitrary commands', now() - interval '4 days'),
    ('88888888-8888-8888-8888-888888880202', '77777777-7777-7777-7777-777777770102',
     'confirmed', 'in_progress', '33333333-3333-3333-3333-333333333303',
     'Assigned to backend team; implementing input validation and sandboxing', now() - interval '3 days'),
    -- XSS: new -> confirmed
    ('88888888-8888-8888-8888-888888880301', '77777777-7777-7777-7777-777777770201',
     'new', 'confirmed', '33333333-3333-3333-3333-333333333303',
     'Confirmed with <script>alert(1)</script> payload in search parameter', now() - interval '2 days'),
    -- SSRF: new -> in_progress
    ('88888888-8888-8888-8888-888888880401', '77777777-7777-7777-7777-777777770202',
     'new', 'in_progress', '33333333-3333-3333-3333-333333333302',
     'Working on URL allow-list implementation for webhook destinations', now() - interval '3 days'),
    -- Path Traversal: new -> confirmed -> resolved
    ('88888888-8888-8888-8888-888888880501', '77777777-7777-7777-7777-777777770203',
     'new', 'confirmed', '33333333-3333-3333-3333-333333333303',
     'Reproduced traversal with ../../etc/passwd payload', now() - interval '5 days'),
    ('88888888-8888-8888-8888-888888880502', '77777777-7777-7777-7777-777777770203',
     'confirmed', 'resolved', '33333333-3333-3333-3333-333333333303',
     'Fixed by replacing user input with basename and validating against allow-list', now() - interval '1 day'),
    -- Broken Auth: new -> confirmed
    ('88888888-8888-8888-8888-888888880601', '77777777-7777-7777-7777-777777770205',
     'new', 'confirmed', '33333333-3333-3333-3333-333333333302',
     'Tested 10k login attempts; no lockout or rate limiting triggered', now() - interval '2 days'),
    -- CSRF: new -> in_progress
    ('88888888-8888-8888-8888-888888880701', '77777777-7777-7777-7777-777777770301',
     'new', 'in_progress', '33333333-3333-3333-3333-333333333303',
     'Adding CSRF token generation to form rendering middleware', now() - interval '1 day'),
    -- Mixed Content: new -> confirmed
    ('88888888-8888-8888-8888-888888880801', '77777777-7777-7777-7777-777777770302',
     'new', 'confirmed', '33333333-3333-3333-3333-333333333302',
     'Verified HTTP CDN script loading via browser dev tools', now() - interval '2 days'),
    -- X-Frame-Options: new -> confirmed
    ('88888888-8888-8888-8888-888888880901', '77777777-7777-7777-7777-777777770306',
     'new', 'confirmed', '33333333-3333-3333-3333-333333333303',
     'Page frameable from external origin; clickjacking POC created', now() - interval '1 day'),
    -- Verbose Errors: new -> confirmed
    ('88888888-8888-8888-8888-888888881001', '77777777-7777-7777-7777-777777770402',
     'new', 'confirmed', '33333333-3333-3333-3333-333333333302',
     'Stack traces visible in API 500 responses; exposes Spring Boot 3.1.2 internals', now() - interval '3 days'),
    -- Email Disclosure: new -> resolved
    ('88888888-8888-8888-8888-888888881101', '77777777-7777-7777-7777-777777770405',
     'new', 'resolved', '33333333-3333-3333-3333-333333333303',
     'Removed HTML comments containing developer email addresses in deploy', now() - interval '1 day'),
    -- Debug endpoint: new -> confirmed
    ('88888888-8888-8888-8888-888888881201', '77777777-7777-7777-7777-777777770503',
     'new', 'confirmed', '33333333-3333-3333-3333-333333333302',
     'pprof endpoint returns heap and goroutine profiles without auth', now() - interval '2 days')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 10. Surface entries
-- ---------------------------------------------------------------------------
INSERT INTO scans.surface_entries (id, project_id, scan_job_id, surface_type, url, method, exposure, title, metadata, finding_ids, observation_count) VALUES
    -- Public route
    ('se01abcdef012345', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'route',
     'https://demo.sentinelcore.io/', 'GET', 'public',
     'Home Page', '{"status_code": 200, "content_type": "text/html"}'::jsonb,
     '{}', 3),
    -- Authenticated route
    ('se02abcdef012345', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'route',
     'https://demo.sentinelcore.io/dashboard', 'GET', 'authenticated',
     'Dashboard', '{"status_code": 200, "content_type": "text/html", "requires_session": true}'::jsonb,
     '{}', 5),
    -- Login form
    ('se03abcdef012345', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'form',
     'https://demo.sentinelcore.io/auth/login', 'POST', 'public',
     'Login Form', '{"fields": ["username", "password", "remember_me"], "action": "/auth/login"}'::jsonb,
     '{}', 2),
    -- Settings form
    ('se04abcdef012345', '44444444-4444-4444-4444-444444444401',
     '66666666-6666-6666-6666-666666666603', 'form',
     'https://demo.sentinelcore.io/settings', 'POST', 'authenticated',
     'Account Settings Form', '{"fields": ["email", "display_name", "password", "confirm_password"], "action": "/settings"}'::jsonb,
     '{}', 1),
    -- API endpoint
    ('se05abcdef012345', '44444444-4444-4444-4444-444444444402',
     '66666666-6666-6666-6666-666666666602', 'api_endpoint',
     'https://api.sentinelcore.io/api/v1/users', 'GET', 'authenticated',
     'Users API Endpoint', '{"response_type": "application/json", "params": ["page", "limit", "sort"]}'::jsonb,
     '{}', 4)
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 11. Governance data
-- ---------------------------------------------------------------------------

-- Org settings
INSERT INTO governance.org_settings (org_id, require_approval_for_risk_acceptance, require_approval_for_false_positive,
                                     require_approval_for_scope_expansion, default_finding_sla_days, updated_by) VALUES
    ('11111111-1111-1111-1111-111111111111', true, true, true,
     '{"critical": 3, "high": 7, "medium": 30, "low": 90}'::jsonb,
     '33333333-3333-3333-3333-333333333301')
ON CONFLICT DO NOTHING;

-- Approval requests
INSERT INTO governance.approval_requests (id, org_id, team_id, request_type, resource_type, resource_id,
                                          requested_by, reason, status, decided_by, decision_reason,
                                          decided_at, expires_at) VALUES
    -- Pending risk acceptance
    ('99999999-9999-9999-9999-999999999901', '11111111-1111-1111-1111-111111111111',
     '22222222-2222-2222-2222-222222222201',
     'risk_acceptance', 'finding', '77777777-7777-7777-7777-777777770401',
     '33333333-3333-3333-3333-333333333303',
     'Password autocomplete is low risk; browser-level control is sufficient for internal app',
     'pending', NULL, NULL, NULL,
     now() + interval '7 days'),
    -- Approved false positive
    ('99999999-9999-9999-9999-999999999902', '11111111-1111-1111-1111-111111111111',
     '22222222-2222-2222-2222-222222222202',
     'false_positive', 'finding', '77777777-7777-7777-7777-777777770404',
     '33333333-3333-3333-3333-333333333303',
     'Internal IP disclosure is expected for health check endpoint behind VPN',
     'approved', '33333333-3333-3333-3333-333333333302',
     'Verified; health endpoint is only accessible from internal network',
     now() - interval '2 days',
     now() + interval '30 days')
ON CONFLICT DO NOTHING;

-- Finding assignments
INSERT INTO governance.finding_assignments (id, finding_id, org_id, team_id, assigned_to, assigned_by, due_at, status, note) VALUES
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa001',
     '77777777-7777-7777-7777-777777770101', '11111111-1111-1111-1111-111111111111',
     '22222222-2222-2222-2222-222222222201',
     '33333333-3333-3333-3333-333333333303', '33333333-3333-3333-3333-333333333302',
     now() + interval '3 days', 'active',
     'Critical SQL injection; prioritize parameterized query migration'),
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa002',
     '77777777-7777-7777-7777-777777770102', '11111111-1111-1111-1111-111111111111',
     '22222222-2222-2222-2222-222222222202',
     '33333333-3333-3333-3333-333333333302', '33333333-3333-3333-3333-333333333301',
     now() + interval '2 days', 'active',
     'RCE is top priority; disable exec endpoint immediately')
ON CONFLICT DO NOTHING;

-- SLA violation
INSERT INTO governance.sla_violations (id, finding_id, org_id, severity, sla_days, deadline_at, violated_at) VALUES
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbb001',
     '77777777-7777-7777-7777-777777770204', '11111111-1111-1111-1111-111111111111',
     'high', 7, now() - interval '1 day', now() - interval '1 day')
ON CONFLICT DO NOTHING;

-- Emergency stop (active, scope: project)
INSERT INTO governance.emergency_stops (id, org_id, scope, scope_id, reason, activated_by) VALUES
    ('cccccccc-cccc-cccc-cccc-ccccccccc001', '11111111-1111-1111-1111-111111111111',
     'project', '44444444-4444-4444-4444-444444444402',
     'Active RCE vulnerability discovered; halting all scans on api-service until remediation is confirmed',
     '33333333-3333-3333-3333-333333333301')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 12. Notifications (5 for admin user)
-- ---------------------------------------------------------------------------
INSERT INTO governance.notifications (id, org_id, user_id, category, title, body, resource_type, resource_id, read) VALUES
    ('dddddddd-dddd-dddd-dddd-ddddddddd001', '11111111-1111-1111-1111-111111111111',
     '33333333-3333-3333-3333-333333333301', 'finding',
     'Critical finding: SQL Injection in UserController',
     'A critical SQL injection vulnerability was detected in the web-application project during SAST scan.',
     'finding', '77777777-7777-7777-7777-777777770101', true),
    ('dddddddd-dddd-dddd-dddd-ddddddddd002', '11111111-1111-1111-1111-111111111111',
     '33333333-3333-3333-3333-333333333301', 'finding',
     'Critical finding: Remote Code Execution via /api/v1/exec',
     'A critical RCE vulnerability was found in the api-service project during DAST scan.',
     'finding', '77777777-7777-7777-7777-777777770102', true),
    ('dddddddd-dddd-dddd-dddd-ddddddddd003', '11111111-1111-1111-1111-111111111111',
     '33333333-3333-3333-3333-333333333301', 'approval',
     'Approval requested: Risk acceptance for password autocomplete finding',
     'analyst@sentinel.io requests risk acceptance approval for a low-severity finding.',
     'approval_request', '99999999-9999-9999-9999-999999999901', false),
    ('dddddddd-dddd-dddd-dddd-ddddddddd004', '11111111-1111-1111-1111-111111111111',
     '33333333-3333-3333-3333-333333333301', 'sla',
     'SLA violation: Insecure Deserialization overdue',
     'High-severity finding on api-service has exceeded the 7-day SLA deadline.',
     'finding', '77777777-7777-7777-7777-777777770204', false),
    ('dddddddd-dddd-dddd-dddd-ddddddddd005', '11111111-1111-1111-1111-111111111111',
     '33333333-3333-3333-3333-333333333301', 'emergency',
     'Emergency stop activated on api-service',
     'All scanning operations on the api-service project have been halted due to an active RCE vulnerability.',
     'project', '44444444-4444-4444-4444-444444444402', false)
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 13. Audit log entries (10)
-- ---------------------------------------------------------------------------
INSERT INTO audit.audit_log (event_id, timestamp, actor_type, actor_id, actor_ip, action, resource_type, resource_id, org_id, team_id, project_id, details, result) VALUES
    -- Admin login
    (gen_random_uuid(), now() - interval '7 days 2 hours', 'user', '33333333-3333-3333-3333-333333333301', '10.0.1.50',
     'auth.login', 'user', '33333333-3333-3333-3333-333333333301',
     '11111111-1111-1111-1111-111111111111', NULL, NULL,
     '{"method": "local", "user_agent": "Mozilla/5.0"}'::jsonb, 'success'),
    -- Security admin login
    (gen_random_uuid(), now() - interval '7 days 1 hour', 'user', '33333333-3333-3333-3333-333333333302', '10.0.1.51',
     'auth.login', 'user', '33333333-3333-3333-3333-333333333302',
     '11111111-1111-1111-1111-111111111111', NULL, NULL,
     '{"method": "local", "user_agent": "Mozilla/5.0"}'::jsonb, 'success'),
    -- SAST scan created
    (gen_random_uuid(), now() - interval '7 days', 'user', '33333333-3333-3333-3333-333333333302', '10.0.1.51',
     'scan.create', 'scan_job', '66666666-6666-6666-6666-666666666601',
     '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222201', '44444444-4444-4444-4444-444444444401',
     '{"scan_type": "sast", "profile": "standard"}'::jsonb, 'success'),
    -- DAST scan created
    (gen_random_uuid(), now() - interval '5 days', 'system', 'scheduler', NULL,
     'scan.create', 'scan_job', '66666666-6666-6666-6666-666666666602',
     '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222202', '44444444-4444-4444-4444-444444444402',
     '{"scan_type": "dast", "profile": "standard", "trigger": "scheduled"}'::jsonb, 'success'),
    -- Finding triage: SQL injection confirmed
    (gen_random_uuid(), now() - interval '6 days', 'user', '33333333-3333-3333-3333-333333333302', '10.0.1.51',
     'finding.triage', 'finding', '77777777-7777-7777-7777-777777770101',
     '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222201', '44444444-4444-4444-4444-444444444401',
     '{"from_status": "new", "to_status": "confirmed", "severity": "critical"}'::jsonb, 'success'),
    -- Finding triage: RCE in_progress
    (gen_random_uuid(), now() - interval '3 days', 'user', '33333333-3333-3333-3333-333333333303', '10.0.1.52',
     'finding.triage', 'finding', '77777777-7777-7777-7777-777777770102',
     '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222202', '44444444-4444-4444-4444-444444444402',
     '{"from_status": "confirmed", "to_status": "in_progress", "severity": "critical"}'::jsonb, 'success'),
    -- Approval: false positive approved
    (gen_random_uuid(), now() - interval '2 days', 'user', '33333333-3333-3333-3333-333333333302', '10.0.1.51',
     'governance.approval.decide', 'approval_request', '99999999-9999-9999-9999-999999999902',
     '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222202', NULL,
     '{"decision": "approved", "request_type": "false_positive"}'::jsonb, 'success'),
    -- Approval: risk acceptance requested
    (gen_random_uuid(), now() - interval '1 day', 'user', '33333333-3333-3333-3333-333333333303', '10.0.1.52',
     'governance.approval.request', 'approval_request', '99999999-9999-9999-9999-999999999901',
     '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222201', NULL,
     '{"request_type": "risk_acceptance", "finding_severity": "low"}'::jsonb, 'success'),
    -- Emergency stop activated
    (gen_random_uuid(), now() - interval '12 hours', 'user', '33333333-3333-3333-3333-333333333301', '10.0.1.50',
     'governance.emergency_stop.activate', 'project', '44444444-4444-4444-4444-444444444402',
     '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222202', '44444444-4444-4444-4444-444444444402',
     '{"scope": "project", "reason": "Active RCE vulnerability"}'::jsonb, 'success'),
    -- Failed login attempt (auditor)
    (gen_random_uuid(), now() - interval '6 hours', 'user', '33333333-3333-3333-3333-333333333304', '192.168.1.100',
     'auth.login', 'user', '33333333-3333-3333-3333-333333333304',
     '11111111-1111-1111-1111-111111111111', NULL, NULL,
     '{"method": "local", "failure_reason": "invalid_password", "user_agent": "Mozilla/5.0"}'::jsonb, 'failure');

COMMIT;
