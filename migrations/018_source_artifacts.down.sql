DROP POLICY IF EXISTS source_artifacts_isolation ON scans.source_artifacts;
DROP INDEX IF EXISTS scans.idx_source_artifacts_project;
DROP TABLE IF EXISTS scans.source_artifacts;
