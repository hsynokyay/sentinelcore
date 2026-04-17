BEGIN;

-- Ring buffer of recent SSO attempts per provider. The admin settings page's
-- test panel reads the last 5-50 entries. This is operational diagnostics
-- (which claims came back, which step failed), NOT the authoritative audit
-- log — that still goes through pkg/audit / NATS. We keep this table small
-- with an automatic retention trigger.
CREATE TABLE auth.sso_login_events (
    id           BIGSERIAL PRIMARY KEY,
    provider_id  UUID NOT NULL REFERENCES auth.oidc_providers(id) ON DELETE CASCADE,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    outcome      TEXT NOT NULL,                     -- 'success' | 'callback_error' | 'claim_error' | 'user_error'
    error_code   TEXT,                              -- e.g. 'state_expired', 'nonce_mismatch', 'aud_mismatch'
    external_id  TEXT,                              -- sub claim if decoded
    email        TEXT,                              -- email claim if decoded
    role_granted TEXT,                              -- resolved role if JIT ran
    claims_redacted JSONB,                          -- full claim payload with values masked to 64 chars max; secret-looking fields removed
    ip_address   INET,                              -- from request
    user_agent   TEXT,
    CONSTRAINT outcome_values CHECK (outcome IN ('success','callback_error','claim_error','user_error'))
);

CREATE INDEX sso_login_events_provider_time_idx
    ON auth.sso_login_events(provider_id, occurred_at DESC);

ALTER TABLE auth.sso_login_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY sso_login_events_isolation ON auth.sso_login_events
    USING (provider_id IN (
        SELECT id FROM auth.oidc_providers
        WHERE org_id = current_setting('app.current_org_id', true)::uuid
    ));

-- Cap per-provider history to 500 rows via AFTER INSERT trigger. Avoids
-- unbounded growth from misconfigured providers that fail every callback.
CREATE OR REPLACE FUNCTION auth.sso_login_events_cap()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = auth, pg_catalog
AS $$
BEGIN
    DELETE FROM auth.sso_login_events
    WHERE provider_id = NEW.provider_id
      AND id NOT IN (
          SELECT id FROM auth.sso_login_events
          WHERE provider_id = NEW.provider_id
          ORDER BY occurred_at DESC
          LIMIT 500
      );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sso_login_events_cap_trg
    AFTER INSERT ON auth.sso_login_events
    FOR EACH ROW
    EXECUTE FUNCTION auth.sso_login_events_cap();

COMMIT;
