BEGIN;

-- Revokes and drops the four split roles introduced in 037.up.sql.
-- Assumes no dependent objects exist: every service container must be
-- re-pointed at the monolithic `sentinelcore` role BEFORE running this.
--
-- Default-privilege reversals must precede DROP ROLE — otherwise the
-- privileges persist on new tables created after the drop.

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA
    core, scans, findings, governance, auth, risk
    REVOKE ALL ON TABLES FROM sentinelcore_controlplane;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA
    core, scans, findings, governance, auth, risk
    REVOKE ALL ON SEQUENCES FROM sentinelcore_controlplane;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA scans, findings, risk
    REVOKE ALL ON TABLES FROM sentinelcore_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA core
    REVOKE ALL ON TABLES FROM sentinelcore_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA audit
    REVOKE ALL ON TABLES FROM sentinelcore_audit_writer;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA
    core, scans, findings, governance, auth, risk, audit
    REVOKE ALL ON TABLES FROM sentinelcore_readonly;

-- REASSIGN is defensive: if anything was created owned by the split
-- roles (shouldn't happen under normal flow) hand it back to the
-- monolithic role before dropping.
DO $$ BEGIN
    EXECUTE 'REASSIGN OWNED BY sentinelcore_controlplane TO sentinelcore';
    EXECUTE 'REASSIGN OWNED BY sentinelcore_audit_writer TO sentinelcore';
    EXECUTE 'REASSIGN OWNED BY sentinelcore_worker TO sentinelcore';
    EXECUTE 'REASSIGN OWNED BY sentinelcore_readonly TO sentinelcore';
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    EXECUTE 'DROP OWNED BY sentinelcore_controlplane';
    EXECUTE 'DROP OWNED BY sentinelcore_audit_writer';
    EXECUTE 'DROP OWNED BY sentinelcore_worker';
    EXECUTE 'DROP OWNED BY sentinelcore_readonly';
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DROP ROLE IF EXISTS sentinelcore_controlplane;
DROP ROLE IF EXISTS sentinelcore_audit_writer;
DROP ROLE IF EXISTS sentinelcore_worker;
DROP ROLE IF EXISTS sentinelcore_readonly;

COMMIT;
