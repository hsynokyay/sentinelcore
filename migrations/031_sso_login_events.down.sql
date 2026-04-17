BEGIN;
DROP TRIGGER IF EXISTS sso_login_events_cap_trg ON auth.sso_login_events;
DROP FUNCTION IF EXISTS auth.sso_login_events_cap();
DROP TABLE IF EXISTS auth.sso_login_events CASCADE;
COMMIT;
