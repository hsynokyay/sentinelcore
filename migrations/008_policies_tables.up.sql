CREATE TABLE policies.policy_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    version         INTEGER NOT NULL DEFAULT 1,
    policy_type     TEXT NOT NULL CHECK (policy_type IN (
                        'access', 'scan', 'gate', 'data', 'network')),
    rego_source     TEXT,
    description     TEXT,
    is_system       BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policies.policy_assignments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies.policy_definitions(id),
    scope_type      TEXT NOT NULL CHECK (scope_type IN ('org', 'team', 'project')),
    scope_id        UUID NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    assigned_by     UUID NOT NULL REFERENCES core.users(id),
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
