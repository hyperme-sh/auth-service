-- Logged, owner-scoped authority. No expiry or automatic tombstone deletion.
CREATE TABLE IF NOT EXISTS auth_nightly_run (
    owner varchar(16) NOT NULL,
    run varchar(128) NOT NULL,
    grant_hash char(64) NOT NULL,
    state jsonb NOT NULL CHECK (jsonb_typeof(state) = 'object' AND octet_length(state::text) <= 131072),
    PRIMARY KEY (owner, run),
    UNIQUE (owner, grant_hash)
);
