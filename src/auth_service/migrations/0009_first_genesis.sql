-- Shared immutable credential ownership also fences older first-link writers.
CREATE TABLE IF NOT EXISTS auth_first_identity_binding (
    credential text PRIMARY KEY CHECK (credential ~ '^[0-9a-f]{64}$'),
    principal text NOT NULL
);
-- statement
CREATE TABLE IF NOT EXISTS auth_first_genesis (
    credential text PRIMARY KEY CHECK (credential ~ '^[0-9a-f]{64}$'),
    principal text NOT NULL UNIQUE,
    output jsonb NOT NULL
);
-- statement
CREATE TABLE IF NOT EXISTS auth_first_genesis_cancel (
    credential text NOT NULL,
    nonce text NOT NULL,
    expires_at bigint NOT NULL,
    PRIMARY KEY (credential,nonce)
);
-- statement
CREATE OR REPLACE FUNCTION auth_first_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE bound_principal text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.credential,0));
    INSERT INTO auth_first_identity_binding(credential,principal) VALUES(NEW.credential,NEW.principal) ON CONFLICT DO NOTHING;
    SELECT principal INTO bound_principal FROM auth_first_identity_binding WHERE credential=NEW.credential;
    IF bound_principal IS DISTINCT FROM NEW.principal THEN
        RAISE EXCEPTION 'first identity binding refused';
    END IF;
    RETURN NEW;
END;
$$;
-- statement
DROP TRIGGER IF EXISTS auth_first_oidc_identity_guard ON auth_first_oidc_link;
-- statement
CREATE TRIGGER auth_first_oidc_identity_guard BEFORE INSERT OR UPDATE ON auth_first_oidc_link
FOR EACH ROW EXECUTE FUNCTION auth_first_identity_guard();
-- statement
DROP TRIGGER IF EXISTS auth_first_genesis_identity_guard ON auth_first_genesis;
-- statement
CREATE TRIGGER auth_first_genesis_identity_guard BEFORE INSERT OR UPDATE ON auth_first_genesis
FOR EACH ROW EXECUTE FUNCTION auth_first_identity_guard();
-- statement
-- Lock existing rows and route backfill through the same guard, refusing conflicts.
UPDATE auth_first_oidc_link SET principal=principal;
-- statement
UPDATE auth_first_genesis SET principal=principal;
