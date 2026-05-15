BEGIN;

ALTER TABLE core.users DROP CONSTRAINT IF EXISTS users_role_check;

UPDATE core.users SET role = 'owner'             WHERE role = 'platform_admin';
UPDATE core.users SET role = 'admin'             WHERE role = 'security_admin';
UPDATE core.users SET role = 'security_engineer' WHERE role = 'appsec_analyst';
-- auditor unchanged.

ALTER TABLE core.users ADD CONSTRAINT users_role_check
    CHECK (role IN ('owner', 'admin', 'security_engineer', 'auditor', 'developer'));

-- Belt-and-braces FK: role must exist in auth.roles.
ALTER TABLE core.users ADD CONSTRAINT users_role_fkey
    FOREIGN KEY (role) REFERENCES auth.roles(id) ON UPDATE CASCADE ON DELETE RESTRICT;

COMMIT;
