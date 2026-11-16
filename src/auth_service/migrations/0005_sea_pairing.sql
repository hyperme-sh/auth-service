-- Logged owner authority: survives process restarts and PostgreSQL recovery.
-- Each explicitly configured scope locks its quotas and sessions atomically.
CREATE TABLE IF NOT EXISTS auth_sea_pairing (
    scope_id char(64) PRIMARY KEY,
    swept_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    state jsonb NOT NULL CHECK (jsonb_typeof(state) = 'object' AND octet_length(state::text) <= 12582912)
);
