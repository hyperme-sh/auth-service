-- Additive authority contract for a fresh configured generation only.
ALTER TABLE users ADD CONSTRAINT uq_scope_users_tenant_id UNIQUE (tenant_id,id);
ALTER TABLE organizations ADD CONSTRAINT uq_scope_orgs_tenant_id UNIQUE (tenant_id,id);
CREATE TABLE identity_scope_schema (revision text PRIMARY KEY, sha256 text NOT NULL);
CREATE TABLE identity_scope_generation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    generation text NOT NULL, manifest_sha256 text NOT NULL CHECK(length(manifest_sha256)=64)
);
CREATE TABLE identity_networks (id text PRIMARY KEY, active boolean NOT NULL);
CREATE TABLE identity_network_tenants (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
    network_id text NOT NULL REFERENCES identity_networks(id)
);
CREATE TABLE identity_network_admins (
    network_id text NOT NULL REFERENCES identity_networks(id),
    user_id uuid NOT NULL REFERENCES users(id),
    active boolean NOT NULL,
    PRIMARY KEY(network_id,user_id)
);
CREATE TABLE identity_org_memberships (
    tenant_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL CHECK(role IN ('admin','member')),
    can_purchase boolean NOT NULL,
    active boolean NOT NULL,
    PRIMARY KEY(organization_id,user_id),
    FOREIGN KEY(tenant_id,organization_id) REFERENCES organizations(tenant_id,id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id)
);
ALTER TABLE identity_network_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_network_tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_network_tenants ON identity_network_tenants
    USING (current_setting('app.current_tenant_id',true)='' OR tenant_id=nullif(current_setting('app.current_tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=nullif(current_setting('app.current_tenant_id',true),'')::uuid);
ALTER TABLE identity_network_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_network_admins FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_network_admins ON identity_network_admins
    USING (current_setting('app.current_tenant_id',true)='')
    WITH CHECK (current_setting('app.current_tenant_id',true)='');
ALTER TABLE identity_org_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_org_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_org_memberships ON identity_org_memberships
    USING (tenant_id=nullif(current_setting('app.current_tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=nullif(current_setting('app.current_tenant_id',true),'')::uuid);
