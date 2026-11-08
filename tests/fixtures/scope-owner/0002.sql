-- User-owned authority scopes. Installed after the immutable fresh owner baseline.
CREATE TABLE authority_networks (
    id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 255),
    enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE authority_network_admins (
    network_id text NOT NULL REFERENCES authority_networks(id),
    user_id uuid NOT NULL REFERENCES users(id),
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY(network_id,user_id)
);
CREATE TABLE authority_tenants (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
    network_id text NOT NULL REFERENCES authority_networks(id)
);
ALTER TABLE users ADD CONSTRAINT authority_user_tenant UNIQUE(id,tenant_id);
ALTER TABLE organizations ADD CONSTRAINT authority_org_tenant UNIQUE(id,tenant_id);
CREATE TABLE organization_memberships (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL CHECK(role IN ('admin','member')),
    can_purchase_leases boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY(tenant_id,organization_id,user_id),
    FOREIGN KEY(user_id,tenant_id) REFERENCES users(id,tenant_id),
    FOREIGN KEY(organization_id,tenant_id) REFERENCES organizations(id,tenant_id)
);
ALTER TABLE authority_networks ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_networks FORCE ROW LEVEL SECURITY;
CREATE POLICY network_scope ON authority_networks USING (id=nullif(current_setting('app.current_network_id',true),'')) WITH CHECK (id=nullif(current_setting('app.current_network_id',true),''));
ALTER TABLE authority_network_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_network_admins FORCE ROW LEVEL SECURITY;
CREATE POLICY network_scope ON authority_network_admins USING (network_id=nullif(current_setting('app.current_network_id',true),'')) WITH CHECK (network_id=nullif(current_setting('app.current_network_id',true),''));
ALTER TABLE authority_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON authority_tenants USING (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''));
ALTER TABLE organization_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON organization_memberships USING (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''));
CREATE FUNCTION require_platform_admin_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND tenant_id IS NULL) THEN
        RAISE EXCEPTION 'Network admin requires a platform identity' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER network_admin_identity BEFORE INSERT OR UPDATE ON authority_network_admins FOR EACH ROW EXECUTE FUNCTION require_platform_admin_identity();
CREATE TABLE authority_fixture_generation (
    generation text PRIMARY KEY,
    manifest_sha256 text NOT NULL CHECK(manifest_sha256 ~ '^[a-f0-9]{64}$'),
    subjects_sha256 text NOT NULL CHECK(subjects_sha256 ~ '^[a-f0-9]{64}$'),
    source_sha text NOT NULL CHECK(source_sha ~ '^[a-f0-9]{40}$'),
    seeded_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE authority_fixture_accounts (
    user_id uuid PRIMARY KEY REFERENCES users(id),
    account_key text NOT NULL UNIQUE,
    network_id text NOT NULL REFERENCES authority_networks(id),
    tenant_context uuid REFERENCES tenants(id)
);
ALTER TABLE authority_fixture_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_fixture_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY network_scope ON authority_fixture_accounts USING (network_id=nullif(current_setting('app.current_network_id',true),'')) WITH CHECK (network_id=nullif(current_setting('app.current_network_id',true),''));
CREATE TRIGGER fixture_platform_identity BEFORE INSERT OR UPDATE ON authority_fixture_accounts FOR EACH ROW EXECUTE FUNCTION require_platform_admin_identity();

CREATE TABLE authority_host_owners (
    tenant_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    PRIMARY KEY(tenant_id,user_id),
    FOREIGN KEY(tenant_id,organization_id,user_id)
        REFERENCES organization_memberships(tenant_id,organization_id,user_id)
);
ALTER TABLE authority_host_owners ENABLE ROW LEVEL SECURITY;
ALTER TABLE authority_host_owners FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON authority_host_owners
    USING (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''))
    WITH CHECK (tenant_id::text=nullif(current_setting('app.current_tenant_id',true),''));
