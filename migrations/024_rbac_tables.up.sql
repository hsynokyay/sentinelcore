BEGIN;

CREATE SCHEMA IF NOT EXISTS auth;

-- ── Create tables ───────────────────────────────────────────────────

CREATE TABLE auth.roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    is_builtin BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.permissions (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    category TEXT NOT NULL
);

CREATE TABLE auth.role_permissions (
    role_id TEXT NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES auth.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ── Seed: roles ─────────────────────────────────────────────────
INSERT INTO auth.roles (id, name, description) VALUES
    ('owner',             'Owner',             'Full control. Only role that can manage users, SSO, or delete the org.'),
    ('admin',             'Admin',             'Full operational control. Settings, scans, targets, API keys, SSO. Cannot manage users.'),
    ('security_engineer', 'Security Engineer', 'Day-to-day security work: scans, triage, risk resolution, audit read.'),
    ('auditor',           'Auditor',           'Read-only across the board + audit log.'),
    ('developer',         'Developer',         'Least privilege: reads risks/findings, acknowledges risks.');

-- ── Seed: permissions ───────────────────────────────────────────
-- 45 permissions total — covers every protected route in the codebase.
-- Before adding or removing a permission, update the route→permission
-- mapping in the plan (Task 7.3).
INSERT INTO auth.permissions (id, description, category) VALUES
    -- risks
    ('risks.read',                 'Read risk clusters',                          'risks'),
    ('risks.resolve',              'Resolve risk clusters',                       'risks'),
    ('risks.mute',                 'Mute risk clusters',                          'risks'),
    ('risks.reopen',               'Reopen risk clusters',                        'risks'),
    ('risks.acknowledge',          'Acknowledge a risk',                          'risks'),
    ('risks.rebuild',              'Rebuild risk correlation for a project',      'risks'),
    -- findings
    ('findings.read',              'Read findings',                               'findings'),
    ('findings.triage',            'Triage findings (assign, set status)',        'findings'),
    ('findings.legal_hold',        'Place legal hold on findings',                'findings'),
    -- scans
    ('scans.read',                 'Read scan jobs',                              'scans'),
    ('scans.run',                  'Run scans',                                   'scans'),
    ('scans.cancel',               'Cancel running scans',                        'scans'),
    -- targets
    ('targets.read',               'Read scan targets',                           'targets'),
    ('targets.manage',             'Create/update/delete scan targets',           'targets'),
    -- projects
    ('projects.read',              'Read projects',                               'projects'),
    ('projects.manage',            'Create/update projects',                      'projects'),
    -- organizations
    ('organizations.read',         'Read organizations',                          'organizations'),
    ('organizations.manage',       'Create/update organizations',                 'organizations'),
    -- teams
    ('teams.read',                 'Read teams and members',                      'teams'),
    ('teams.manage',               'Create teams, manage membership',             'teams'),
    -- auth profiles (DAST credentials)
    ('authprofiles.read',          'Read DAST auth profiles',                     'authprofiles'),
    ('authprofiles.manage',        'Create/update/delete DAST auth profiles',     'authprofiles'),
    -- artifacts (SAST source uploads)
    ('artifacts.read',             'Read source artifacts',                       'artifacts'),
    ('artifacts.manage',           'Upload/delete source artifacts',              'artifacts'),
    -- governance
    ('governance.approvals.read',  'Read approval requests',                      'governance'),
    ('governance.approvals.decide','Approve or reject approval requests',         'governance'),
    ('governance.estop.activate',  'Activate emergency stop',                     'governance'),
    ('governance.estop.lift',      'Lift emergency stop',                         'governance'),
    ('governance.estop.read',      'Read active emergency stops',                 'governance'),
    -- settings
    ('settings.read',              'Read org settings',                           'settings'),
    ('settings.manage',            'Modify org settings',                         'settings'),
    -- users
    ('users.read',                 'List users',                                  'users'),
    ('users.manage',               'Create/update/delete users, change roles',    'users'),
    -- api_keys
    ('api_keys.read',              'List API keys',                               'api_keys'),
    ('api_keys.manage',            'Create/rotate/revoke API keys',               'api_keys'),
    -- sso (Phase 3 uses this)
    ('sso.manage',                 'Configure SSO providers + group mappings',    'sso'),
    -- audit
    ('audit.read',                 'Read audit log',                              'audit'),
    -- webhooks
    ('webhooks.read',              'Read webhook configs',                        'webhooks'),
    ('webhooks.manage',            'Create/update/delete/test webhook configs',   'webhooks'),
    -- retention
    ('retention.read',             'Read retention policies + records',           'retention'),
    ('retention.manage',           'Update retention policies',                   'retention'),
    -- reports
    ('reports.read',               'Read aggregate reports',                      'reports'),
    -- surface (attack surface inventory)
    ('surface.read',               'Read attack surface entries + stats',         'surface'),
    -- notifications (per-user; read-only user view)
    ('notifications.read',         'Read own notifications',                      'notifications'),
    -- ops (platform-level observability)
    ('ops.read',                   'Read platform ops metrics',                   'ops');

-- ── Seed: role_permissions ──────────────────────────────────────
-- owner: everything
INSERT INTO auth.role_permissions (role_id, permission_id)
    SELECT 'owner', id FROM auth.permissions;

-- admin: everything except users.manage
INSERT INTO auth.role_permissions (role_id, permission_id)
    SELECT 'admin', id FROM auth.permissions WHERE id <> 'users.manage';

-- security_engineer: operational work, no settings/users/keys/sso/org/retention
INSERT INTO auth.role_permissions (role_id, permission_id) VALUES
    ('security_engineer','risks.read'),
    ('security_engineer','risks.resolve'),
    ('security_engineer','risks.mute'),
    ('security_engineer','risks.reopen'),
    ('security_engineer','risks.acknowledge'),
    ('security_engineer','risks.rebuild'),
    ('security_engineer','findings.read'),
    ('security_engineer','findings.triage'),
    ('security_engineer','scans.read'),
    ('security_engineer','scans.run'),
    ('security_engineer','scans.cancel'),
    ('security_engineer','targets.read'),
    ('security_engineer','targets.manage'),
    ('security_engineer','projects.read'),
    ('security_engineer','organizations.read'),
    ('security_engineer','teams.read'),
    ('security_engineer','authprofiles.read'),
    ('security_engineer','authprofiles.manage'),
    ('security_engineer','artifacts.read'),
    ('security_engineer','artifacts.manage'),
    ('security_engineer','governance.approvals.read'),
    ('security_engineer','governance.estop.activate'),
    ('security_engineer','governance.estop.read'),
    ('security_engineer','settings.read'),
    ('security_engineer','audit.read'),
    ('security_engineer','webhooks.read'),
    ('security_engineer','reports.read'),
    ('security_engineer','surface.read'),
    ('security_engineer','notifications.read');

-- auditor: read-only everywhere (incl. audit log)
INSERT INTO auth.role_permissions (role_id, permission_id) VALUES
    ('auditor','risks.read'),
    ('auditor','findings.read'),
    ('auditor','scans.read'),
    ('auditor','targets.read'),
    ('auditor','projects.read'),
    ('auditor','organizations.read'),
    ('auditor','teams.read'),
    ('auditor','authprofiles.read'),
    ('auditor','artifacts.read'),
    ('auditor','governance.approvals.read'),
    ('auditor','governance.estop.read'),
    ('auditor','settings.read'),
    ('auditor','users.read'),
    ('auditor','api_keys.read'),
    ('auditor','audit.read'),
    ('auditor','webhooks.read'),
    ('auditor','retention.read'),
    ('auditor','reports.read'),
    ('auditor','surface.read'),
    ('auditor','notifications.read');

-- developer: least privilege
INSERT INTO auth.role_permissions (role_id, permission_id) VALUES
    ('developer','risks.read'),
    ('developer','risks.acknowledge'),
    ('developer','findings.read'),
    ('developer','scans.read'),
    ('developer','targets.read'),
    ('developer','projects.read'),
    ('developer','notifications.read');

COMMIT;
