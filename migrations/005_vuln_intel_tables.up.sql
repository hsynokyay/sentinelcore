CREATE TABLE vuln_intel.vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id          TEXT UNIQUE,
    source          TEXT NOT NULL CHECK (source IN ('nvd', 'osv', 'github', 'cisa_kev')),
    title           TEXT NOT NULL,
    description     TEXT,
    cvss_v31_score  NUMERIC(3,1),
    cvss_v31_vector TEXT,
    epss_score      NUMERIC(5,4),
    epss_percentile NUMERIC(5,4),
    cwe_ids         INTEGER[],
    affected_products JSONB,
    exploit_available BOOLEAN NOT NULL DEFAULT false,
    exploit_sources  TEXT[],
    actively_exploited BOOLEAN NOT NULL DEFAULT false,
    published_at    TIMESTAMPTZ,
    modified_at     TIMESTAMPTZ,
    kev_added_at    TIMESTAMPTZ,
    references      JSONB,
    raw_data        JSONB,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vuln_cve ON vuln_intel.vulnerabilities(cve_id);
CREATE INDEX idx_vuln_source ON vuln_intel.vulnerabilities(source);
CREATE INDEX idx_vuln_exploited ON vuln_intel.vulnerabilities(actively_exploited)
    WHERE actively_exploited = true;

CREATE TABLE vuln_intel.package_vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id UUID NOT NULL REFERENCES vuln_intel.vulnerabilities(id),
    ecosystem       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    version_range   TEXT NOT NULL,
    fixed_version   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pkg_vuln_lookup ON vuln_intel.package_vulnerabilities(ecosystem, package_name);

CREATE TABLE vuln_intel.feed_sync_status (
    feed_name       TEXT PRIMARY KEY,
    last_sync_at    TIMESTAMPTZ,
    last_sync_status TEXT NOT NULL DEFAULT 'never',
    records_synced  INTEGER DEFAULT 0,
    next_sync_at    TIMESTAMPTZ,
    error_message   TEXT
);
