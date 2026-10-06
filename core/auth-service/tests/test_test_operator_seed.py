import uuid
import pytest
from auth_service import test_operator_seed as seed


def claims():
    return {"iss":"https://auth.test.hyperme.sh/realms/controlplane", "email":seed.EMAIL,
            "email_verified":True,"preferred_username":"admin","sub":"kc-admin",
            "realm_access":{"roles":["admin"]}}


def test_bootstrap_requires_explicit_opt_in_and_test_issuer(monkeypatch):
    monkeypatch.setattr(seed.settings,"keycloak_issuer",claims()["iss"])
    monkeypatch.delenv("PANOPTICON_TEST_OPERATOR_BOOTSTRAP",raising=False)
    assert not seed.eligible(claims(),seed.MARKETPLACE_TENANT_ID)
    monkeypatch.setenv("PANOPTICON_TEST_OPERATOR_BOOTSTRAP","1")
    assert seed.eligible(claims(),seed.MARKETPLACE_TENANT_ID)
    assert not seed.eligible(claims(),uuid.uuid4())
    monkeypatch.setattr(seed.settings,"keycloak_issuer","https://auth.hyperme.sh/realms/controlplane")
    assert not seed.eligible(claims(),seed.MARKETPLACE_TENANT_ID)


@pytest.mark.parametrize("key,value",[("email_verified",False),("email","renter@test.hyperme.sh"),("realm_access",{"roles":["renter"]}),("sub",""),("iss","https://evil.invalid"),("purpose","host-setup"),("panopticon_auth","tenant_session")])
def test_bootstrap_rejects_other_identities(monkeypatch,key,value):
    monkeypatch.setattr(seed.settings,"keycloak_issuer",claims()["iss"])
    monkeypatch.setenv("PANOPTICON_TEST_OPERATOR_BOOTSTRAP","1")
    assert not seed.eligible({**claims(),key:value},seed.MARKETPLACE_TENANT_ID)


@pytest.mark.parametrize("username", ["admin", seed.EMAIL, "renamed-account", "", None])
def test_username_is_not_an_authorization_requirement(monkeypatch, username):
    monkeypatch.setattr(seed.settings, "keycloak_issuer", claims()["iss"])
    monkeypatch.setenv("PANOPTICON_TEST_OPERATOR_BOOTSTRAP", "1")
    identity = {**claims(), "preferred_username": username}
    if username is None:
        identity.pop("preferred_username")
    assert seed.eligible(identity, seed.MARKETPLACE_TENANT_ID)
    assert not seed.eligible({**identity, "realm_access": {"roles": []}}, seed.MARKETPLACE_TENANT_ID)


@pytest.mark.asyncio
async def test_rejected_seed_logs_checks_without_identity_material(monkeypatch, caplog):
    monkeypatch.setattr(seed.settings, "keycloak_issuer", claims()["iss"])
    monkeypatch.setenv("PANOPTICON_TEST_OPERATOR_BOOTSTRAP", "1")
    identity = {**claims(), "preferred_username": "private-username", "sub": "private-subject",
                "realm_access": {"roles": []}}
    await seed.provision_test_operator(identity, seed.MARKETPLACE_TENANT_ID)
    assert "checks=admin_role" in caplog.text
    assert "private-" not in caplog.text
    assert seed.EMAIL not in caplog.text
