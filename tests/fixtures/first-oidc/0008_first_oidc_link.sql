-- Durable first credential binding. Expiration never frees it for another owner.
CREATE TABLE IF NOT EXISTS auth_first_oidc_link (
    credential text PRIMARY KEY CHECK (credential ~ '^[0-9a-f]{64}$'),
    principal text NOT NULL,
    output jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_first_oidc_cancel (
    credential text NOT NULL,
    nonce text NOT NULL,
    expires_at bigint NOT NULL,
    PRIMARY KEY (credential, nonce)
);
