CREATE TABLE rules.rule_sets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    version         TEXT NOT NULL,
    source          TEXT NOT NULL CHECK (source IN ('builtin', 'vendor', 'custom')),
    engine_type     TEXT NOT NULL CHECK (engine_type IN ('sast', 'dast')),
    description     TEXT,
    checksum        TEXT NOT NULL,
    signature       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rules.rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_set_id     UUID NOT NULL REFERENCES rules.rule_sets(id),
    rule_id         TEXT NOT NULL,
    engine_type     TEXT NOT NULL CHECK (engine_type IN ('sast', 'dast')),
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    cwe_id          INTEGER,
    owasp_category  TEXT,
    language        TEXT,
    rule_definition JSONB NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    tags            TEXT[] DEFAULT '{}',
    references      TEXT[],
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_set_id, rule_id)
);
