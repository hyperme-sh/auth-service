from auth_service.claims import groups_from_claims
from auth_service.schemas import AuthMeResponse


def test_groups_from_claims_accepts_keycloak_paths():
    assert groups_from_claims({"groups": ["/host", "/renter"]}) == [
        "/host",
        "/renter",
    ]
    assert groups_from_claims({"group": "billing"}) == ["billing"]
    assert groups_from_claims({}) == []


def test_auth_me_from_claims_includes_groups_and_roles():
    me = AuthMeResponse.from_claims(
        {
            "sub": "u1",
            "email": "a@example.com",
            "realm_access": {"roles": ["admin"]},
            "groups": ["/host"],
            "tenant_id": "00000000-0000-0000-0000-000000000001",
        }
    )
    assert me.roles == ["admin"]
    assert me.groups == ["/host"]
    assert str(me.tenant_id) == "00000000-0000-0000-0000-000000000001"
