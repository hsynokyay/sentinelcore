-- Refuse to roll back if unprocessed audit events still exist — otherwise
-- legitimate key-revocation events would be silently dropped (violates
-- the at-least-once audit delivery guarantee the up migration promises).
-- Operators who intend to accept the loss can manually truncate first.
BEGIN;
DO $$
DECLARE
    pending_count INT;
BEGIN
    SELECT COUNT(*) INTO pending_count FROM auth.pending_audit_events WHERE processed = false;
    IF pending_count > 0 THEN
        RAISE EXCEPTION 'refusing to roll back 028: % unprocessed audit events in auth.pending_audit_events. Drain the queue (wait for the controlplane drainer) or truncate manually with: DELETE FROM auth.pending_audit_events WHERE processed = false;', pending_count;
    END IF;
END $$;
DROP TRIGGER IF EXISTS users_role_change_revoke_keys ON core.users;
DROP FUNCTION IF EXISTS auth.revoke_excess_scope_keys_on_role_change();
DROP TABLE IF EXISTS auth.pending_audit_events;
COMMIT;
