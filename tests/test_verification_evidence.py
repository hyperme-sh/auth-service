import pytest
from auth_service.verification_evidence import email_evidence

ENV = {"AUTH_VERIFICATION_EMAIL_ISSUER":"https://id.test/realms/production", "AUTH_VERIFICATION_EMAIL_PROVIDERS":"google"}
CLAIMS = {"iss":ENV["AUTH_VERIFICATION_EMAIL_ISSUER"], "azp":"controlplane-frontend", "identity_provider":"google", "email":"owner@example.test", "email_verified":True}

def test_explicit_broker_policy():
    assert email_evidence(CLAIMS, ENV)["email_verified"] is True
    assert email_evidence(CLAIMS, {})["email_verified"] is False

@pytest.mark.parametrize('change', [{'iss':'https://evil.test'}, {'azp':'other'}, {'identity_provider':'untrusted'}, {'identity_provider':None}, {'email_verified':'true'}, {'email':None}])
def test_forged_or_untrusted_claims(change):
    assert email_evidence(CLAIMS | change, ENV) == {"email":None, "email_verified":False}
