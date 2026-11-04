from controlplane_tenancy.marketplace import MARKETPLACE_TENANT_ID
"""Setup identity cannot become a general tenant credential."""
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import InvalidTokenError

from api.core.config import settings
from api.infrastructure.security.keycloak_jwt import KeycloakJWTValidator
from api.infrastructure.security.tenant_session_jwt import (
    mint_host_setup_session, mint_tenant_session_jwt,
    try_decode_host_setup_session, try_decode_tenant_session_jwt,
)
from auth_service import routes
from auth_service.tenant_switch import TenantSwitchGrant

CLIENT = "hypermesh-host-setup"

@pytest.fixture
def oidc(app, monkeypatch):
    async def fake_session():
        return object()
    app.dependency_overrides[routes.get_db_session] = fake_session
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    validator = KeycloakJWTValidator("https://unused", "https://issuer.test", "unused")
    validator._jwks_client = SimpleNamespace(get_signing_key_from_jwt=lambda _: SimpleNamespace(key=key.public_key()))
    from api.infrastructure.security import keycloak_jwt
    monkeypatch.setattr(keycloak_jwt, "get_keycloak_jwt_validator", lambda: validator)
    monkeypatch.setattr("auth_service.token_validation.get_keycloak_jwt_validator", lambda: validator)
    # Even a stale explicit allowlist cannot widen the dedicated client's access.
    monkeypatch.setattr(settings, "keycloak_allowed_client_ids", CLIENT + ",controlplane-frontend")
    def issue(**changes):
        claims = {"iss": "https://issuer.test", "aud": CLIENT, "azp": CLIENT,
                  "sub": "owner", "email": "owner@example.com", "exp": int(time.time()) + 300}
        claims.update(changes)
        return jwt.encode(claims, key, algorithm="RS256")
    return validator, issue


def test_keycloak_host_setup_requires_own_audience_and_client(oidc):
    validator, issue = oidc
    assert validator.validate_host_setup_sync(issue())["sub"] == "owner"
    with pytest.raises(InvalidTokenError):
        validator.validate_sync(issue())
    for changes in ({"azp": "controlplane-frontend"}, {"aud": "account"}, {"exp": 1}):
        with pytest.raises(InvalidTokenError):
            validator.validate_host_setup_sync(issue(**changes))


async def test_setup_session_strips_tenant_authority_and_generic_routes_reject_it(
    app, http_client, tenant_uuid, oidc, monkeypatch, event_sink,
):
    _, issue = oidc
    token = issue(permissions=["HOST_MANAGE_TENANTS"], realm_access={"roles": ["admin"]})
    headers = {"Authorization": "Bearer " + token}
    grant = AsyncMock(return_value=TenantSwitchGrant(role_name="admin", permissions=["HOST_MANAGE_TENANTS"]))
    monkeypatch.setattr(routes, "authorize_tenant_switch", grant)
    assert (await http_client.get("/auth/host-setup/me", headers=headers)).status_code == 200
    response = await http_client.post("/auth/host-setup/session", headers=headers, json={"tenant_id": str(tenant_uuid)})
    assert response.status_code == 200, response.text
    assert event_sink[-1]["payload"]["grant_type"] == "host_setup"
    setup_token = response.json()["access_token"]
    claims = try_decode_host_setup_session(setup_token)
    assert claims["purpose"] == "host_setup" and claims["tenant_id"] == str(tenant_uuid)
    assert not ({"permissions", "realm_access", "groups", "spanopticon_auth"} & claims.keys())
    assert try_decode_tenant_session_jwt(setup_token) is None
    with pytest.raises(ValueError):
        mint_tenant_session_jwt(claims={"sub": "owner", "azp": CLIENT}, tenant_id=tenant_uuid)
    for credential in (token, setup_token):
        headers = {"Authorization": "Bearer " + credential}
        for path, body in (("/auth/switch-tenant", {"tenant_id": str(tenant_uuid)}),
                           ("/auth/enrollment/grant", {"tenant_id": str(tenant_uuid), "held_roles": ["renter"]})):
            assert (await http_client.post(path, headers=headers, json=body)).status_code == 401
        assert (await http_client.get("/auth/me", headers=headers)).status_code == 401
        assert (await http_client.get("/auth/tenant", headers=headers)).status_code == 401


async def test_setup_session_requires_membership_and_matching_tenant(http_client, tenant_uuid, oidc, monkeypatch):
    _, issue = oidc
    grant = AsyncMock(return_value=None)
    monkeypatch.setattr(routes, "authorize_tenant_switch", grant)
    headers = {"Authorization": "Bearer " + issue()}
    assert (await http_client.post("/auth/host-setup/session", headers=headers, json={"tenant_id": str(tenant_uuid)})).status_code == 403
    grant.assert_awaited_once()
    headers["X-Tenant-ID"] = "00000000-0000-0000-0000-000000000000"
    assert (await http_client.post("/auth/host-setup/session", headers=headers, json={"tenant_id": str(tenant_uuid)})).status_code == 403
    grant.assert_awaited_once()


@pytest.mark.parametrize("roles", [["admin"], ["renter"], ["host", "admin"], [], None])
async def test_setup_grant_cannot_request_other_roles(http_client, tenant_uuid, oidc, roles):
    _, issue = oidc
    response = await http_client.post("/auth/host-setup/enrollment/grant", headers={"Authorization": "Bearer " + issue()},
        json={"tenant_id": str(tenant_uuid), "held_roles": roles})
    assert response.status_code == 403, response.text


async def test_host_membership_grant_drops_other_identity_authority(http_client, tenant_uuid, oidc, monkeypatch):
    from auth_service.enrollment import EnrollmentGrantResult
    _, issue = oidc
    grant = AsyncMock(return_value=EnrollmentGrantResult(granted=("host",), refused=(), wallet_address=None))
    monkeypatch.setattr(routes, "grant_held_roles", grant)
    response = await http_client.post("/auth/host-setup/enrollment/grant",
        headers={"Authorization": "Bearer " + issue(realm_access={"roles": ["admin"]}, groups=["admin"])},
        json={"tenant_id": str(MARKETPLACE_TENANT_ID), "held_roles": ["host"]})
    assert response.status_code == 200, response.text
    assert response.json()["granted"] == ["host"]
    user = grant.await_args.args[1]
    assert user.sub == "owner" and user.roles == [] and user.groups == []
    assert grant.await_args.kwargs["requested"] == ["host"]


@pytest.mark.parametrize("change", [{"purpose": "service"}, {"aud": "account"}, {"exp": 1}, {"iss": "other"}])
def test_setup_session_rejects_wrong_purpose_audience_issuer_or_expiry(app, tenant_uuid, change):
    token = mint_host_setup_session(claims={"azp": CLIENT, "sub": "owner"}, tenant_id=tenant_uuid)
    claims = try_decode_host_setup_session(token)
    claims.update(change)
    altered = jwt.encode(claims, settings.usable_api_key_exchange_secret(), algorithm="HS256")
    assert try_decode_host_setup_session(altered) is None


def test_old_generic_setup_session_is_rejected(app, tenant_uuid):
    from api.infrastructure.security.tenant_session_jwt import ISSUER
    token = jwt.encode({"iss": ISSUER, "sub": "owner", "azp": CLIENT,
        "spanopticon_auth": "tenant_session", "tenant_id": str(tenant_uuid),
        "exp": int(time.time()) + 300}, settings.usable_api_key_exchange_secret(), algorithm="HS256")
    assert try_decode_tenant_session_jwt(token) is None


@pytest.mark.parametrize("identity", [{"azp": CLIENT}, {"client_id": CLIENT}])
async def test_generic_introspection_rejects_setup_client(app, monkeypatch, identity):
    from api.common.exceptions import UnauthorizedException
    from auth_service import token_validation
    monkeypatch.setattr(settings, "auth_token_validation_mode", "introspection")
    monkeypatch.setattr(token_validation, "introspect_access_token", AsyncMock(return_value={"active": True, **identity}))
    with pytest.raises(UnauthorizedException):
        await token_validation.validate_access_token("opaque-device-token")


async def test_banned_member_cannot_exchange_setup_session(http_client, tenant_uuid, oidc, monkeypatch):
    import uuid
    from api.domain.operator import bans
    _, issue = oidc
    monkeypatch.setattr(routes, "authorize_tenant_switch", AsyncMock(return_value=TenantSwitchGrant(role_name="admin", user_id=uuid.uuid4())))
    monkeypatch.setattr(bans, "ban_book", lambda: SimpleNamespace(user_may_enter=lambda *_: False))
    response = await http_client.post("/auth/host-setup/session", headers={"Authorization": "Bearer " + issue()},
        json={"tenant_id": str(tenant_uuid)})
    assert response.status_code == 403
