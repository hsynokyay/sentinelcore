DROP POLICY IF EXISTS taint_paths_isolation ON findings.taint_paths;
DROP INDEX IF EXISTS findings.idx_taint_paths_finding;
DROP TABLE IF EXISTS findings.taint_paths;
