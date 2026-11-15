-- Nullable nonce and defaulted attempts preserve older PostgreSQL writers.
ALTER TABLE auth_siwe_challenges ADD COLUMN IF NOT EXISTS nonce text;
ALTER TABLE auth_siwe_challenges ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX IF NOT EXISTS auth_siwe_challenges_nonce ON auth_siwe_challenges(nonce);
-- Delivery must survive restart and failover; unlike challenges this is logged.
CREATE TABLE IF NOT EXISTS auth_wallet_commands (
    id uuid PRIMARY KEY,
    subject_hash char(64) NOT NULL UNIQUE,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
