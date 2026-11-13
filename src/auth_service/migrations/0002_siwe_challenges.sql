-- Non-durable, short-lived challenges. Crash/failover loss requires a fresh nonce.
CREATE UNLOGGED TABLE IF NOT EXISTS auth_siwe_challenges (
    subject_hash char(64) PRIMARY KEY,
    challenge jsonb NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_siwe_challenges_expiry ON auth_siwe_challenges(expires_at);
