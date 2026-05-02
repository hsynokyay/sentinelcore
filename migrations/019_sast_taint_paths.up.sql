-- Chunk SAST-7: findings pipeline integration.
--
-- findings.taint_paths stores the evidence chain for each SAST finding.
-- Each row is one step in the source → propagation → sink trace. The UI
-- renders these as a collapsible "Analysis Trace" block in the finding
-- detail page.

CREATE TABLE IF NOT EXISTS findings.taint_paths (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID NOT NULL REFERENCES findings.findings(id) ON DELETE CASCADE,
    step_index  INTEGER NOT NULL,
    file_path   TEXT NOT NULL,
    line_start  INTEGER NOT NULL,
    line_end    INTEGER,
    step_kind   TEXT NOT NULL CHECK (step_kind IN ('source', 'propagation', 'sink')),
    detail      TEXT NOT NULL,
    function_fqn TEXT,
    UNIQUE (finding_id, step_index)
);

CREATE INDEX IF NOT EXISTS idx_taint_paths_finding ON findings.taint_paths(finding_id);

-- RLS: inherit from the parent finding's project isolation.
ALTER TABLE findings.taint_paths ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS taint_paths_isolation ON findings.taint_paths;
CREATE POLICY taint_paths_isolation ON findings.taint_paths
    USING (finding_id IN (
        SELECT id FROM findings.findings
         WHERE project_id IN (
             SELECT id FROM core.projects
              WHERE org_id = current_setting('app.org_id', true)::uuid
         )
    ));
