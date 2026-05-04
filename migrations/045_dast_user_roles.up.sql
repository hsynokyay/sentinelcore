-- DAST-specific role grants. Independent of the global Role in JWT — a user
-- can have a global Role of "user" but be granted "dast.recording_reviewer"
-- here. Roles are namespaced "dast.*".
CREATE TABLE dast_user_roles (
    user_id     UUID NOT NULL,
    role        TEXT NOT NULL CHECK (role IN (
        'dast.recorder',
        'dast.recording_reviewer',
        'dast.scan_operator',
        'dast.recording_admin',
        'dast.audit_viewer'
    )),
    granted_by  UUID NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ,
    PRIMARY KEY (user_id, role)
);

CREATE INDEX dast_user_roles_user ON dast_user_roles(user_id) WHERE revoked_at IS NULL;
CREATE INDEX dast_user_roles_role ON dast_user_roles(role) WHERE revoked_at IS NULL;

-- 4-eyes trigger: a bundle can only transition to 'approved' status if the
-- approver_user_id is different from the recorder (created_by_user_id).
CREATE OR REPLACE FUNCTION enforce_dast_bundle_4eyes()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'approved' AND OLD.status != 'approved' THEN
        IF NEW.approved_by_user_id IS NULL THEN
            RAISE EXCEPTION '4-eyes: approved_by_user_id required';
        END IF;
        IF NEW.approved_by_user_id = NEW.created_by_user_id THEN
            RAISE EXCEPTION '4-eyes: recorder cannot approve own recording (recorder=%, reviewer=%)',
                NEW.created_by_user_id, NEW.approved_by_user_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER dast_bundle_4eyes_check
BEFORE UPDATE ON dast_auth_bundles
FOR EACH ROW
EXECUTE FUNCTION enforce_dast_bundle_4eyes();
