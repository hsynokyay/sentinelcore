CREATE TABLE core.organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE core.teams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES core.organizations(id),
    name            TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE core.users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES core.organizations(id),
    username        TEXT NOT NULL,
    email           TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    password_hash   TEXT,
    identity_provider TEXT NOT NULL DEFAULT 'local',
    external_id     TEXT,
    role            TEXT NOT NULL DEFAULT 'appsec_analyst'
                    CHECK (role IN ('platform_admin', 'security_admin', 'appsec_analyst', 'auditor')),
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled', 'locked')),
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, username),
    UNIQUE (org_id, email)
);

CREATE TABLE core.team_memberships (
    team_id         UUID NOT NULL REFERENCES core.teams(id),
    user_id         UUID NOT NULL REFERENCES core.users(id),
    role            TEXT NOT NULL CHECK (role IN (
                        'team_admin', 'security_lead', 'analyst',
                        'developer', 'viewer')),
    granted_by      UUID NOT NULL REFERENCES core.users(id),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE core.projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES core.organizations(id),
    team_id         UUID NOT NULL REFERENCES core.teams(id),
    name            TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    description     TEXT,
    repository_url  TEXT,
    default_branch  TEXT DEFAULT 'main',
    asset_criticality TEXT NOT NULL DEFAULT 'medium'
                    CHECK (asset_criticality IN ('critical', 'high', 'medium', 'low')),
    scan_config     JSONB NOT NULL DEFAULT '{}',
    tags            TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'archived', 'deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE core.scan_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    target_type     TEXT NOT NULL CHECK (target_type IN ('web_app', 'api', 'graphql')),
    base_url        TEXT NOT NULL,
    allowed_domains TEXT[] NOT NULL,
    allowed_paths   TEXT[],
    excluded_paths  TEXT[],
    allowed_ports   INTEGER[] NOT NULL DEFAULT '{80, 443}',
    max_rps         INTEGER NOT NULL DEFAULT 10,
    auth_config_id  UUID,
    verified_at     TIMESTAMPTZ,
    verified_by     UUID REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE core.target_verifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id       UUID NOT NULL REFERENCES core.scan_targets(id),
    method          TEXT NOT NULL CHECK (method IN ('dns_txt', 'http_wellknown', 'admin_approval')),
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'verified', 'expired', 'failed')),
    token           TEXT NOT NULL,
    verified_at     TIMESTAMPTZ,
    verified_by     UUID REFERENCES core.users(id),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '90 days'),
    justification   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
