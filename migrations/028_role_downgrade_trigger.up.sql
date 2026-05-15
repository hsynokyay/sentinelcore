-- When a user's role is downgraded, auto-revoke user-owned API keys whose
-- scopes exceed the new role's permissions. Runs in the same transaction
-- as the UPDATE OF role so there is NO window where the old role is
-- visible to other transactions while the keys still work (TOCTOU closure).
--
-- Service-account keys (is_service_account=true) are NOT revoked — that's
-- the whole point of service accounts (they outlive the creator's role).

BEGIN;

-- Small side table for events that trigger functions can't emit directly.
-- org_id is included directly (not just in details JSONB) so the drainer
-- can tenant-scope NATS emissions without JSONB parsing. Must come before
-- the trigger function since the function inserts into this table.
CREATE TABLE IF NOT EXISTS auth.pending_audit_events (
    id          BIGSERIAL PRIMARY KEY,
    org_id      UUID NOT NULL,
    event_type  TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    details     JSONB NOT NULL,
    processed   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pending_audit_events_unprocessed_idx
    ON auth.pending_audit_events (org_id, created_at) WHERE processed = false;

-- SECURITY DEFINER is required: the trigger fires under whatever session
-- triggered the UPDATE on core.users, which may or may not have
-- app.current_org_id set (an admin CLI path may not set it). The function
-- must query auth.role_permissions (global) and update core.api_keys
-- regardless of RLS on the calling session. search_path is pinned to
-- prevent search-path injection attacks (standard PG hardening).
CREATE OR REPLACE FUNCTION auth.revoke_excess_scope_keys_on_role_change()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = auth, core, pg_catalog
AS $$
DECLARE
    new_role_perms TEXT[];
    key_record RECORD;
BEGIN
    -- Only act on actual role change.
    IF NEW.role IS NOT DISTINCT FROM OLD.role THEN
        RETURN NEW;
    END IF;

    -- Load the new role's permission set.
    SELECT array_agg(permission_id) INTO new_role_perms
    FROM auth.role_permissions
    WHERE role_id = NEW.role;

    -- If the new role has no permissions (unknown role), skip to avoid
    -- revoking everything accidentally. A proper check constraint on
    -- core.users.role + the auth.roles FK (Phase 1 migration 025) already
    -- prevents unknown roles, but we belt-and-brace.
    IF new_role_perms IS NULL THEN
        RETURN NEW;
    END IF;

    -- Find user-owned keys with scopes exceeding the new role.
    -- NOTE: PostgreSQL core does NOT provide `-` (set-difference) on
    -- text[] — only the `intarray` extension provides it, and only for
    -- integer[]. So we use an EXISTS subquery to check "does the key have
    -- any scope not in new_role_perms" without the extension dependency.
    FOR key_record IN
        SELECT id, prefix FROM core.api_keys
        WHERE user_id = NEW.id
          AND is_service_account = false
          AND revoked = false
          AND array_length(scopes, 1) > 0
          AND EXISTS (
              SELECT 1
              FROM unnest(scopes) AS scope
              WHERE scope <> ALL (new_role_perms)
          )
    LOOP
        UPDATE core.api_keys
        SET revoked = true
        WHERE id = key_record.id;

        -- Emit a marker for the audit emitter (emitted from app code on
        -- COMMIT — the trigger itself can't reach NATS directly).
        -- We record the intent in a side table that the app reads post-commit.
        -- org_id is populated directly from the triggering user row so the
        -- drainer can tenant-scope the NATS emission.
        INSERT INTO auth.pending_audit_events (org_id, event_type, resource_id, details, created_at)
        VALUES (
            NEW.org_id,
            'api_key.auto_revoke',
            key_record.id::text,
            jsonb_build_object(
                'reason', 'role_downgrade',
                'prefix', key_record.prefix,
                'user_id', NEW.id,
                'org_id', NEW.org_id,
                'old_role', OLD.role,
                'new_role', NEW.role
            ),
            now()
        );
    END LOOP;

    -- Notify the session-revoke listener so it invalidates JTIs in Redis.
    -- Payload = user_id. The listener parses this and runs SREM on the
    -- session-tracking Redis key for that user.
    PERFORM pg_notify('user_sessions_revoke', NEW.id::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Ensure the function is owned by a superuser or the schema owner so
-- SECURITY DEFINER runs with appropriate privileges. In this codebase
-- migrations run as the `sentinelcore` user which owns both schemas, so
-- no explicit OWNER change is needed — but we assert it:
DO $$
BEGIN
    IF (SELECT proowner FROM pg_proc WHERE proname = 'revoke_excess_scope_keys_on_role_change') <>
       (SELECT oid FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'function owner mismatch — SECURITY DEFINER may not bypass RLS as expected';
    END IF;
END $$;

CREATE TRIGGER users_role_change_revoke_keys
    AFTER UPDATE OF role ON core.users
    FOR EACH ROW
    EXECUTE FUNCTION auth.revoke_excess_scope_keys_on_role_change();

COMMIT;
