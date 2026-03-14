-- Enable RLS on key tables
ALTER TABLE findings.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans.scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.projects ENABLE ROW LEVEL SECURITY;

-- Findings: visible only to team members
CREATE POLICY findings_team_access ON findings.findings
    USING (
        project_id IN (
            SELECT p.id FROM core.projects p
            JOIN core.team_memberships tm ON tm.team_id = p.team_id
            WHERE tm.user_id = current_setting('app.current_user_id')::UUID
        )
    );

-- Scans: visible only to team members
CREATE POLICY scans_team_access ON scans.scan_jobs
    USING (
        project_id IN (
            SELECT p.id FROM core.projects p
            JOIN core.team_memberships tm ON tm.team_id = p.team_id
            WHERE tm.user_id = current_setting('app.current_user_id')::UUID
        )
    );

-- Projects: visible only to team members
CREATE POLICY projects_team_access ON core.projects
    USING (
        team_id IN (
            SELECT tm.team_id FROM core.team_memberships tm
            WHERE tm.user_id = current_setting('app.current_user_id')::UUID
        )
    );
