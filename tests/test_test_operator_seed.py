import uuid
import pytest
from user_service import identity_test_seed as seed


def claims():
    return {"iss":"https://auth.test.hyperme.sh/realms/controlplane", "email":seed.EMAIL,
            "email_verified":True,"preferred_username":"admin","sub":"kc-admin",
            "realm_access":{"roles":["admin"]}}


def test_bootstrap_requires_explicit_opt_in_and_test_issuer(monkeypatch):
    monkeypatch.setattr(seed.settings,"keycloak_issuer",claims()["iss"])
    monkeypatch.delenv("SPANOPTICON_TEST_OPERATOR_BOOTSTRAP",raising=False)
    assert not seed.eligible(claims(),seed.MARKETPLACE_TENANT_ID)
    monkeypatch.setenv("SPANOPTICON_TEST_OPERATOR_BOOTSTRAP","1")
    assert seed.eligible(claims(),seed.MARKETPLACE_TENANT_ID)
    assert not seed.eligible(claims(),uuid.uuid4())
    monkeypatch.setattr(seed.settings,"keycloak_issuer","https://auth.hyperme.sh/realms/controlplane")
    assert not seed.eligible(claims(),seed.MARKETPLACE_TENANT_ID)


@pytest.mark.parametrize("key,value",[("email_verified",False),("email","renter@test.hyperme.sh"),("realm_access",{"roles":["renter"]}),("sub",""),("iss","https://evil.invalid"),("purpose","host-setup"),("spanopticon_auth","tenant_session")])
def test_bootstrap_rejects_other_identities(monkeypatch,key,value):
    monkeypatch.setattr(seed.settings,"keycloak_issuer",claims()["iss"])
    monkeypatch.setenv("SPANOPTICON_TEST_OPERATOR_BOOTSTRAP","1")
    assert not seed.eligible({**claims(),key:value},seed.MARKETPLACE_TENANT_ID)


@pytest.mark.parametrize("username", ["admin", seed.EMAIL, "renamed-account", "", None])
def test_username_is_not_an_authorization_requirement(monkeypatch, username):
    monkeypatch.setattr(seed.settings, "keycloak_issuer", claims()["iss"])
    monkeypatch.setenv("SPANOPTICON_TEST_OPERATOR_BOOTSTRAP", "1")
    identity = {**claims(), "preferred_username": username}
    if username is None:
        identity.pop("preferred_username")
    assert seed.eligible(identity, seed.MARKETPLACE_TENANT_ID)
    assert not seed.eligible({**identity, "realm_access": {"roles": []}}, seed.MARKETPLACE_TENANT_ID)


@pytest.mark.asyncio
async def test_rejected_seed_logs_checks_without_identity_material(monkeypatch, caplog):
    monkeypatch.setattr(seed.settings, "keycloak_issuer", claims()["iss"])
    monkeypatch.setenv("SPANOPTICON_TEST_OPERATOR_BOOTSTRAP", "1")
    identity = {**claims(), "preferred_username": "private-username", "sub": "private-subject",
                "realm_access": {"roles": []}}
    await seed.provision_test_operator(identity, seed.MARKETPLACE_TENANT_ID)
    assert "checks=admin_role" in caplog.text
    assert "private-" not in caplog.text
    assert seed.EMAIL not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("realm_access", [None, "admin", ["admin"], 42,
    {"roles": None}, {"roles": "admin"}, {"roles": {"admin": True}}, {"roles": 42}])
@pytest.mark.parametrize("mode", ["test", "disabled", "production", "other_tenant"])
async def test_malformed_roles_skip_bootstrap_without_database_access(monkeypatch, realm_access, mode):
    issuer = claims()["iss"] if mode != "production" else "https://auth.hyperme.sh/realms/controlplane"
    monkeypatch.setattr(seed.settings, "keycloak_issuer", issuer)
    monkeypatch.setenv("SPANOPTICON_TEST_OPERATOR_BOOTSTRAP", "0" if mode == "disabled" else "1")
    tenant = uuid.uuid4() if mode == "other_tenant" else seed.MARKETPLACE_TENANT_ID
    identity = {**claims(), "iss": issuer, "realm_access": realm_access}
    assert "admin_role" in seed.eligibility_failures(identity, tenant)
    assert not seed.eligible(identity, tenant)
    await seed.provision_test_operator(identity, tenant)


def test_sqlstate_reads_the_driver_code():
    class Orig:
        sqlstate = "42501"
    exc = Exception()
    assert seed._sqlstate(exc) is None
    exc.orig = Orig()
    assert seed._sqlstate(exc) == "42501"
    exc.orig = type("Pg", (), {"pgcode": "23505"})()
    assert seed._sqlstate(exc) == "23505"


def test_username_fallback_is_only_for_a_missing_email():
    assert seed._host_email({"email": " Leaser@test.hyperme.sh "}) == seed.HOST_EMAIL
    assert seed._host_email({"preferred_username": "leaser"}) == seed.HOST_EMAIL
    assert seed._host_email({"email": "other@test.hyperme.sh", "preferred_username": "leaser"}) == "other@test.hyperme.sh"
    assert seed._host_email({"preferred_username": "renter"}) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("claims_body,issuer,tenant", [
    ({"iss": seed.TEST_ISSUER, "email": "renter@test.hyperme.sh", "sub": "x"}, seed.TEST_ISSUER, None),
    ({"iss": seed.TEST_ISSUER, "email": seed.HOST_EMAIL, "sub": "x", "purpose": "host-setup"}, seed.TEST_ISSUER, None),
    ({"iss": "https://auth.hyperme.sh/realms/controlplane", "email": seed.HOST_EMAIL, "sub": "x"}, seed.TEST_ISSUER, None),
    ({"iss": seed.TEST_ISSUER, "email": seed.HOST_EMAIL, "sub": "x"}, "https://auth.hyperme.sh/realms/controlplane", None),
    ({"iss": seed.TEST_ISSUER, "preferred_username": "leaser", "email": "other@test.hyperme.sh", "sub": "x"}, seed.TEST_ISSUER, None),
])
async def test_seeded_host_role_does_not_touch_other_identities(monkeypatch, claims_body, issuer, tenant):
    monkeypatch.setattr(seed.settings, "keycloak_issuer", issuer)

    class Boom:
        async def scalars(self, *_args, **_kwargs):
            raise AssertionError("database")

    await seed.ensure_seeded_host_role(
        claims_body, tenant or seed.MARKETPLACE_TENANT_ID, Boom(),
    )


@pytest.mark.parametrize("issuer", [None, 42, [], {}])
def test_malformed_issuer_is_a_failed_check(monkeypatch, issuer):
    monkeypatch.setattr(seed.settings, "keycloak_issuer", claims()["iss"])
    monkeypatch.setenv("SPANOPTICON_TEST_OPERATOR_BOOTSTRAP", "1")
    assert "token_issuer" in seed.eligibility_failures({**claims(), "iss": issuer}, seed.MARKETPLACE_TENANT_ID)
