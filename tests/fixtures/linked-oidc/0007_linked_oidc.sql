-- Private, durable, bounded proof attempts. No identity enrollment or session issuance.
CREATE TABLE IF NOT EXISTS auth_linked_oidc (
    domain char(64) PRIMARY KEY,
    expires_at bigint NOT NULL,
    state jsonb NOT NULL CHECK (jsonb_typeof(state) = 'object' AND octet_length(state::text) <= 8388608)
);
