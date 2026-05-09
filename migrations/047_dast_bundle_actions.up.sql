ALTER TABLE dast_auth_bundles
    ADD COLUMN action_count INT NOT NULL DEFAULT 0;

CREATE INDEX dast_auth_bundles_action_count
    ON dast_auth_bundles(action_count)
    WHERE type = 'recorded_login' AND action_count > 0;
