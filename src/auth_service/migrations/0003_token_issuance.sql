-- Owner issuance decisions contain a digest only; no bearer tokens or signatures.
CREATE TABLE IF NOT EXISTS auth_token_issuance (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    token_sha256 char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, token_sha256)
);
ALTER TABLE auth_token_issuance ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_token_issuance FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS auth_token_issuance_tenant ON auth_token_issuance;
CREATE POLICY auth_token_issuance_tenant ON auth_token_issuance
USING (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid);
