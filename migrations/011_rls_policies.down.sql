DROP POLICY IF EXISTS projects_team_access ON core.projects;
DROP POLICY IF EXISTS scans_team_access ON scans.scan_jobs;
DROP POLICY IF EXISTS findings_team_access ON findings.findings;
ALTER TABLE core.projects DISABLE ROW LEVEL SECURITY;
ALTER TABLE scans.scan_jobs DISABLE ROW LEVEL SECURITY;
ALTER TABLE findings.findings DISABLE ROW LEVEL SECURITY;
