ALTER TABLE findings.findings DROP COLUMN IF EXISTS function_name;
DROP TABLE IF EXISTS risk.cluster_relations;
DROP TABLE IF EXISTS risk.cluster_evidence;
DROP TABLE IF EXISTS risk.cluster_findings;
DROP TABLE IF EXISTS risk.clusters;
DROP TABLE IF EXISTS risk.correlation_runs;
DROP SCHEMA IF EXISTS risk;
