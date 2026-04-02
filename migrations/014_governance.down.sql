-- migrations/014_governance.down.sql
-- Rollback Phase 4: Enterprise Governance schema

ALTER TABLE findings.findings DROP COLUMN IF EXISTS org_id;
ALTER TABLE findings.findings DROP COLUMN IF EXISTS assigned_to;
ALTER TABLE findings.findings DROP COLUMN IF EXISTS sla_deadline;
ALTER TABLE findings.findings DROP COLUMN IF EXISTS legal_hold;

ALTER TABLE scans.scan_jobs DROP COLUMN IF EXISTS emergency_stopped;
ALTER TABLE scans.scan_jobs DROP COLUMN IF EXISTS stopped_by;
ALTER TABLE scans.scan_jobs DROP COLUMN IF EXISTS stopped_reason;

DROP SCHEMA IF EXISTS governance CASCADE;
