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


@pytest.mark.parametrize("key,value",[("email_verified",False),("email","renter@test.hyperme.sh"),("realm_access",{"roles":["renter"]}),("preferred_username","other"),("sub",""),("iss","https://evil.invalid"),("purpose","host-setup"),("panopticon_auth","tenant_session")])
def test_bootstrap_rejects_other_identities(monkeypatch,key,value):
    monkeypatch.setattr(seed.settings,"keycloak_issuer",claims()["iss"])
    monkeypatch.setenv("PANOPTICON_TEST_OPERATOR_BOOTSTRAP","1")
    assert not seed.eligible({**claims(),key:value},seed.MARKETPLACE_TENANT_ID)
