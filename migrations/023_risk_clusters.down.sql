-- Reverse of 023_risk_clusters.up.sql.
-- Drop the risk schema first (always unblocked since it's isolated);
-- drop the findings.function_name column last so a lock on findings.findings
-- does not prevent rolling back the risk.* tables.

DROP TABLE IF EXISTS risk.cluster_relations;
DROP TABLE IF EXISTS risk.cluster_evidence;
DROP TABLE IF EXISTS risk.cluster_findings;
DROP TABLE IF EXISTS risk.clusters;
DROP TABLE IF EXISTS risk.correlation_runs;
DROP SCHEMA IF EXISTS risk;

ALTER TABLE findings.findings DROP COLUMN IF EXISTS function_name;
