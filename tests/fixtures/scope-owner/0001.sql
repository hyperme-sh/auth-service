-- Fresh owner baseline. Foreign identity references are validated over HTTP.


CREATE TABLE account_lifecycles (
	subject VARCHAR(512) NOT NULL,
	requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
	requested_by VARCHAR(512) NOT NULL,
	source VARCHAR(16) NOT NULL,
	state VARCHAR(16) NOT NULL,
	closed_at TIMESTAMP WITH TIME ZONE,
	profile_deleted_at TIMESTAMP WITH TIME ZONE,
	financial_deleted_at TIMESTAMP WITH TIME ZONE,
	financial_retain_until TIMESTAMP WITH TIME ZONE,
	financial_epoch BIGINT DEFAULT '0' NOT NULL,
	financial_hold BOOLEAN NOT NULL,
	hold_reference VARCHAR(128),
	claim_id UUID,
	claim_until TIMESTAMP WITH TIME ZONE,
	retry_at TIMESTAMP WITH TIME ZONE NOT NULL,
	last_error VARCHAR(64),
	effects JSONB NOT NULL,
	PRIMARY KEY (subject),
	CONSTRAINT ck_account_lifecycle_subject CHECK (length(btrim(subject)) > 0),
	CONSTRAINT ck_account_lifecycle_state CHECK (state IN ('closing','closed','deleting','deleted'))
)

;

CREATE INDEX ix_account_lifecycle_work ON account_lifecycles (state, retry_at);


CREATE TABLE identity_retirements (
	subject VARCHAR(512) NOT NULL,
	retired_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (subject)
)

;


CREATE TABLE operator_mail_quota (
	year_month VARCHAR(7) NOT NULL,
	sent_count INTEGER NOT NULL,
	PRIMARY KEY (year_month)
)

;


CREATE TABLE tenants (
	id UUID NOT NULL,
	name VARCHAR(512) NOT NULL,
	subdomain VARCHAR(512),
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	is_active BOOLEAN NOT NULL,
	custom_domain VARCHAR(512),
	custom_domain_status VARCHAR(64) DEFAULT 'failed' NOT NULL,
	features JSONB,
	subscription_id UUID,
	PRIMARY KEY (id),
	UNIQUE (name),
	UNIQUE (subdomain),
	UNIQUE (custom_domain)
)

;


CREATE TABLE user_wallet_bindings (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	keycloak_sub VARCHAR(512) NOT NULL,
	email VARCHAR(512),
	wallet_address VARCHAR(42) NOT NULL,
	bound_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id)
)

;

CREATE UNIQUE INDEX uq_user_wallet_bindings_address ON user_wallet_bindings (wallet_address);

CREATE UNIQUE INDEX uq_user_wallet_bindings_sub ON user_wallet_bindings (keycloak_sub);


CREATE TABLE account_closure_requests (
	tenant_id UUID NOT NULL,
	subject VARCHAR(512) NOT NULL,
	requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
	requested_by VARCHAR(512) NOT NULL,
	source VARCHAR(16) NOT NULL,
	PRIMARY KEY (tenant_id, subject),
	CONSTRAINT ck_account_closure_subject CHECK (length(btrim(subject)) > 0),
	CONSTRAINT ck_account_closure_source CHECK (source IN ('self_service', 'operator')),
	CONSTRAINT ck_account_closure_actor CHECK (length(btrim(requested_by)) > 0),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE RESTRICT
)

;

CREATE INDEX ix_account_closure_requested ON account_closure_requests (tenant_id, requested_at, subject);

ALTER TABLE "account_closure_requests" ENABLE ROW LEVEL SECURITY; ALTER TABLE "account_closure_requests" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "account_closure_requests" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE account_lifecycle_scopes (
	tenant_id UUID NOT NULL,
	subject VARCHAR(512) NOT NULL,
	user_ids JSONB NOT NULL,
	effects JSONB NOT NULL,
	PRIMARY KEY (tenant_id, subject),
	FOREIGN KEY(subject) REFERENCES account_lifecycles (subject) ON DELETE RESTRICT,
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE RESTRICT
)

;

ALTER TABLE "account_lifecycle_scopes" ENABLE ROW LEVEL SECURITY; ALTER TABLE "account_lifecycle_scopes" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "account_lifecycle_scopes" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE api_keys (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID NOT NULL,
	key_prefix VARCHAR(32) NOT NULL,
	secret_hash VARCHAR(128) NOT NULL,
	name VARCHAR(256),
	scopes JSONB,
	created_by_sub VARCHAR(512),
	revoked_at TIMESTAMP WITH TIME ZONE,
	purpose VARCHAR(32) NOT NULL,
	last_used_at TIMESTAMP WITH TIME ZONE,
	key_fingerprint VARCHAR(64),
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
	CONSTRAINT uq_api_keys_prefix UNIQUE (key_prefix)
)

;

CREATE INDEX ix_api_keys_tenant ON api_keys (tenant_id);

ALTER TABLE "api_keys" ENABLE ROW LEVEL SECURITY; ALTER TABLE "api_keys" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "api_keys" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE operator_audit (
	id UUID NOT NULL,
	tenant_id UUID NOT NULL,
	actor VARCHAR(512) NOT NULL,
	action VARCHAR(64) NOT NULL,
	target_kind VARCHAR(32) NOT NULL,
	target_id VARCHAR(64) NOT NULL,
	reason TEXT NOT NULL,
	detail JSONB DEFAULT '{}'::jsonb NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

CREATE INDEX ix_operator_audit_tenant ON operator_audit (tenant_id);

ALTER TABLE "operator_audit" ENABLE ROW LEVEL SECURITY; ALTER TABLE "operator_audit" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "operator_audit" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE operator_bans (
	id UUID NOT NULL,
	tenant_id UUID NOT NULL,
	subject_kind VARCHAR(16) NOT NULL,
	subject_id UUID NOT NULL,
	reason TEXT NOT NULL,
	created_by VARCHAR(512) NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	lifted_at TIMESTAMP WITH TIME ZONE,
	lifted_by VARCHAR(512),
	lift_reason TEXT,
	subject_label VARCHAR(512),
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

CREATE INDEX ix_operator_bans_tenant ON operator_bans (tenant_id);

CREATE UNIQUE INDEX uq_operator_bans_active ON operator_bans (tenant_id, subject_kind, subject_id) WHERE lifted_at IS NULL;

ALTER TABLE "operator_bans" ENABLE ROW LEVEL SECURITY; ALTER TABLE "operator_bans" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "operator_bans" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE operator_peers (
	id UUID NOT NULL,
	tenant_id UUID NOT NULL,
	display_name VARCHAR(256) NOT NULL,
	base_url VARCHAR(512) NOT NULL,
	peer_tenant_id VARCHAR(64) NOT NULL,
	last_health_ok BOOLEAN NOT NULL,
	last_health_detail VARCHAR(500) NOT NULL,
	checked_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

CREATE INDEX ix_operator_peers_tenant ON operator_peers (tenant_id);

ALTER TABLE "operator_peers" ENABLE ROW LEVEL SECURITY; ALTER TABLE "operator_peers" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "operator_peers" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE organizations (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID NOT NULL,
	legal_name VARCHAR(512) NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT uq_organizations_id_tenant UNIQUE (id, tenant_id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

CREATE UNIQUE INDEX uq_organizations_tenant_legal_name ON organizations (tenant_id, legal_name);

ALTER TABLE "organizations" ENABLE ROW LEVEL SECURITY; ALTER TABLE "organizations" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "organizations" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE roles (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID,
	name VARCHAR(255) NOT NULL,
	description TEXT,
	permissions JSONB DEFAULT '[]'::jsonb NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

CREATE UNIQUE INDEX uq_roles_platform_name ON roles (name) WHERE tenant_id IS NULL;

CREATE UNIQUE INDEX uq_roles_tenant_name ON roles (tenant_id, name) WHERE tenant_id IS NOT NULL;

ALTER TABLE "roles" ENABLE ROW LEVEL SECURITY; ALTER TABLE "roles" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "roles" USING ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL))) WITH CHECK ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL)));


CREATE TABLE user_passkey_challenges (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID,
	email VARCHAR(512) NOT NULL,
	type VARCHAR(32) NOT NULL,
	challenge TEXT NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

ALTER TABLE "user_passkey_challenges" ENABLE ROW LEVEL SECURITY; ALTER TABLE "user_passkey_challenges" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "user_passkey_challenges" USING ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL))) WITH CHECK ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL)));


CREATE TABLE user_passkeys (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID,
	user_email VARCHAR(512) NOT NULL,
	credentials JSONB DEFAULT '[]'::jsonb NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

ALTER TABLE "user_passkeys" ENABLE ROW LEVEL SECURITY; ALTER TABLE "user_passkeys" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "user_passkeys" USING ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL))) WITH CHECK ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL)));


CREATE TABLE groups (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID NOT NULL,
	name VARCHAR(255) NOT NULL,
	description TEXT,
	role_id UUID NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
	FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE RESTRICT
)

;

CREATE UNIQUE INDEX uq_groups_tenant_name ON groups (tenant_id, name);

ALTER TABLE "groups" ENABLE ROW LEVEL SECURITY; ALTER TABLE "groups" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "groups" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE organization_idp_links (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID NOT NULL,
	organization_id UUID NOT NULL,
	provider VARCHAR(32) NOT NULL,
	external_key VARCHAR(256) NOT NULL,
	linked_by_sub VARCHAR(512) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
	FOREIGN KEY(organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
	CONSTRAINT uq_org_idp_provider_key UNIQUE (tenant_id, provider, external_key)
)

;

ALTER TABLE "organization_idp_links" ENABLE ROW LEVEL SECURITY; ALTER TABLE "organization_idp_links" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "organization_idp_links" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE users (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID,
	first_name VARCHAR(255) NOT NULL,
	last_name VARCHAR(255) NOT NULL,
	email VARCHAR(512) NOT NULL,
	gender VARCHAR(64) NOT NULL,
	role_id UUID,
	is_active BOOLEAN NOT NULL,
	activated_at TIMESTAMP WITH TIME ZONE,
	image_url TEXT,
	password TEXT,
	sso_provider_id VARCHAR(512),
	keycloak_sub VARCHAR(512),
	deleted_at TIMESTAMP WITH TIME ZONE,
	sociacl_attributes JSONB,
	PRIMARY KEY (id),
	FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE SET NULL,
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

CREATE UNIQUE INDEX uq_users_platform_email ON users (email) WHERE tenant_id IS NULL;

CREATE UNIQUE INDEX uq_users_platform_keycloak_sub ON users (keycloak_sub) WHERE tenant_id IS NULL AND keycloak_sub IS NOT NULL;

CREATE UNIQUE INDEX uq_users_tenant_email ON users (tenant_id, email) WHERE tenant_id IS NOT NULL;

CREATE UNIQUE INDEX uq_users_tenant_keycloak_sub ON users (tenant_id, keycloak_sub) WHERE tenant_id IS NOT NULL AND keycloak_sub IS NOT NULL;

ALTER TABLE "users" ENABLE ROW LEVEL SECURITY; ALTER TABLE "users" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "users" USING ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL))) WITH CHECK ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL)));


CREATE TABLE subscription_plans (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID,
	plan_level JSONB NOT NULL,
	is_trial BOOLEAN NOT NULL,
	actor VARCHAR(32) NOT NULL,
	user_id UUID,
	plan_id VARCHAR(255) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE SET NULL,
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

ALTER TABLE "subscription_plans" ENABLE ROW LEVEL SECURITY; ALTER TABLE "subscription_plans" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "subscription_plans" USING ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL))) WITH CHECK ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL)));


CREATE TABLE user_group_memberships (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID NOT NULL,
	user_id UUID NOT NULL,
	group_id UUID NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(group_id) REFERENCES groups (id) ON DELETE CASCADE,
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)

;

CREATE UNIQUE INDEX uq_user_group_memberships_user_group ON user_group_memberships (user_id, group_id);

ALTER TABLE "user_group_memberships" ENABLE ROW LEVEL SECURITY; ALTER TABLE "user_group_memberships" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "user_group_memberships" USING (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'')) WITH CHECK (tenant_id::text = nullif(current_setting('app.current_tenant_id',true),''));


CREATE TABLE user_magic_links (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID,
	user_id UUID NOT NULL,
	token TEXT NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)

;

ALTER TABLE "user_magic_links" ENABLE ROW LEVEL SECURITY; ALTER TABLE "user_magic_links" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "user_magic_links" USING ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL))) WITH CHECK ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL)));


CREATE TABLE user_password_resets (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID,
	user_id UUID NOT NULL,
	token_secret TEXT NOT NULL,
	reset_secret_updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
	first_name VARCHAR(255) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
)

;

ALTER TABLE "user_password_resets" ENABLE ROW LEVEL SECURITY; ALTER TABLE "user_password_resets" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "user_password_resets" USING ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL))) WITH CHECK ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL)));


CREATE TABLE user_preferences (
	id UUID NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	tenant_id UUID,
	user_id UUID NOT NULL,
	preferences JSONB DEFAULT '{}'::jsonb NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
)

;

ALTER TABLE "user_preferences" ENABLE ROW LEVEL SECURITY; ALTER TABLE "user_preferences" FORCE ROW LEVEL SECURITY; CREATE POLICY owner_tenant ON "user_preferences" USING ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL))) WITH CHECK ((tenant_id::text = nullif(current_setting('app.current_tenant_id',true),'') OR (tenant_id IS NULL AND nullif(current_setting('app.current_tenant_id',true),'') IS NULL)));


CREATE TABLE service_outbox (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    envelope jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX service_outbox_pending ON service_outbox(created_at, id)
    WHERE delivered_at IS NULL;
ALTER TABLE service_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY service_outbox_tenant ON service_outbox
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);



CREATE TABLE event_inbox (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    envelope jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE event_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_inbox FORCE ROW LEVEL SECURITY;
CREATE POLICY event_inbox_tenant ON event_inbox
USING (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid);

