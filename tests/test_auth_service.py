from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import jwt
import pytest
import respx
from httpx import Response

from api.common.event_types import AUTH_LOGIN_SUCCESS_V1, AUTH_TOKEN_ISSUED_V1
from api.common.exceptions import UnauthorizedException
from api.core import config as api_config


def _sample_access_jwt(*, sub: str = "u1", tenant_id: str | None = None) -> str:
    payload: dict = {"sub": sub}
    if tenant_id:
        payload["tenant_id"] = tenant_id
    return jwt.encode(
        payload,
        "unit-test-hmac-secret-at-least-32-bytes-long",
        algorithm="HS256",
    )


@pytest.mark.asyncio
async def test_login_returns_keycloak_authorization_url(http_client):
    r = await http_client.post("/auth/login", json={})
    assert r.status_code == 200
    data = r.json()
    assert "authorization_url" in data
    assert "state" in data
    assert "keycloak.test/realms/demo/protocol/openid-connect/auth" in data["authorization_url"]
    assert "client_id=test-client" in data["authorization_url"]


@pytest.mark.asyncio
async def test_login_accepts_identity_provider_hint(http_client):
    r = await http_client.post("/auth/login", json={"identity_provider_hint": "google"})
    assert r.status_code == 200
    url = r.json()["authorization_url"]
    assert "kc_idp_hint=google" in url


@pytest.mark.asyncio
@respx.mock
async def test_callback_exchanges_code_and_publishes_events(app, event_sink, http_client):
    tid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    access = _sample_access_jwt(sub="u1", tenant_id=tid)
    token_url = "http://keycloak.test/realms/demo/protocol/openid-connect/token"
    respx.post(token_url).mock(
        return_value=Response(
            200,
            json={
                "access_token": access,
                "refresh_token": "rt1",
                "expires_in": 300,
                "token_type": "Bearer",
            },
        )
    )

    r = await http_client.get("/auth/callback", params={"code": "abc", "state": "s"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"]
    assert body["refresh_token"] == "rt1"

    types = [e["event_type"] for e in event_sink]
    assert AUTH_LOGIN_SUCCESS_V1 in types
    assert AUTH_TOKEN_ISSUED_V1 in types
    login_ev = next(e for e in event_sink if e["event_type"] == AUTH_LOGIN_SUCCESS_V1)
    assert login_ev["payload"]["subject"] == "u1"


@pytest.mark.asyncio
@respx.mock
async def test_refresh_publishes_token_issued(event_sink, http_client):
    token_url = "http://keycloak.test/realms/demo/protocol/openid-connect/token"
    respx.post(token_url).mock(
        return_value=Response(
            200,
            json={
                "access_token": _sample_access_jwt(sub="u2"),
                "expires_in": 60,
                "token_type": "Bearer",
            },
        )
    )
    r = await http_client.post("/auth/refresh", json={"refresh_token": "old"})
    assert r.status_code == 200
    assert any(e["event_type"] == AUTH_TOKEN_ISSUED_V1 for e in event_sink)


@pytest.mark.asyncio
async def test_me_valid_token_extracts_user_and_tenant(
    app, http_client, tenant_uuid, monkeypatch
):
    from auth_service import deps

    async def fake_claims() -> dict:
        return {
            "sub": "sub-1",
            "email": "u@example.com",
            "preferred_username": "user1",
            "tenant_id": str(tenant_uuid),
            "realm_access": {"roles": ["tenant-user"]},
            "scope": "openid profile",
            "amr": ["pwd", "otp"],
        }

    app.dependency_overrides[deps.get_access_token_claims] = fake_claims
    try:
        r = await http_client.get(
            "/auth/me", headers={"Authorization": "Bearer fake.jwt"}
        )
        assert r.status_code == 200
        me = r.json()
        assert me["sub"] == "sub-1"
        assert me["email"] == "u@example.com"
        assert me["tenant_id"] == str(tenant_uuid)
        assert "tenant-user" in me["roles"]
        assert "openid" in me["scopes"]
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


@pytest.mark.asyncio
async def test_me_invalid_token_returns_401(app, http_client):
    from auth_service import deps

    async def boom():
        raise UnauthorizedException("Invalid or expired access token")

    app.dependency_overrides[deps.get_access_token_claims] = boom
    try:
        r = await http_client.get(
            "/auth/me", headers={"Authorization": "Bearer bad"}
        )
        assert r.status_code == 401
        assert "Invalid" in r.json()["error"]
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


@pytest.mark.asyncio
async def test_me_missing_bearer_returns_401(http_client):
    r = await http_client.get("/auth/me")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_tenant_route_missing_tenant_claim_returns_403(app, http_client):
    from auth_service import deps

    async def claims_no_tenant() -> dict:
        return {
            "sub": "x",
            "email": "a@b.com",
            "realm_access": {"roles": []},
            "scope": "openid",
        }

    app.dependency_overrides[deps.get_access_token_claims] = claims_no_tenant
    try:
        r = await http_client.get(
            "/auth/tenant", headers={"Authorization": "Bearer t"}
        )
        assert r.status_code == 403
        assert "tenant" in r.json()["error"].lower()
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


@pytest.mark.asyncio
async def test_mfa_enforcement_blocks_me_without_amr(
    app, http_client, tenant_uuid, monkeypatch
):
    monkeypatch.setattr(api_config.settings, "oidc_require_mfa", True)

    claims_no_mfa = {
        "sub": "sub-mfa",
        "email": "m@example.com",
        "tenant_id": str(tenant_uuid),
        "realm_access": {"roles": []},
        "scope": "openid",
        "amr": ["pwd"],
    }

    with patch(
        "auth_service.deps.validate_access_token",
        new=AsyncMock(return_value=claims_no_mfa),
    ):
        r = await http_client.get(
            "/auth/me", headers={"Authorization": "Bearer x"}
        )
        assert r.status_code == 403
        assert "MFA" in r.json()["error"]


@pytest.mark.asyncio
@respx.mock
async def test_introspection_mode_valid_active_token(
    app, http_client, tenant_uuid, monkeypatch
):
    monkeypatch.setattr(api_config.settings, "auth_token_validation_mode", "introspection")
    introspect_url = "http://keycloak.test/realms/demo/protocol/openid-connect/token/introspect"
    respx.post(introspect_url).mock(
        return_value=Response(
            200,
            json={
                "active": True,
                "sub": "intro-1",
                "username": "user@example.com",
                "scope": "openid email",
                "realm_access": {"roles": ["user"]},
                "tenant_id": str(tenant_uuid),
            },
        )
    )

    r = await http_client.get(
        "/auth/me", headers={"Authorization": "Bearer opaque-token"}
    )
    assert r.status_code == 200
    me = r.json()
    assert me["sub"] == "intro-1"


@pytest.mark.asyncio
@respx.mock
async def test_introspection_inactive_returns_401(http_client, monkeypatch):
    monkeypatch.setattr(api_config.settings, "auth_token_validation_mode", "introspection")
    introspect_url = "http://keycloak.test/realms/demo/protocol/openid-connect/token/introspect"
    respx.post(introspect_url).mock(
        return_value=Response(200, json={"active": False}),
    )
    r = await http_client.get(
        "/auth/me", headers={"Authorization": "Bearer dead"}
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_marketplace_discovery_uses_configured_tenant(http_client, monkeypatch):
    import uuid
    from controlplane_tenancy import marketplace
    tenant = uuid.UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    monkeypatch.setattr(marketplace, "MARKETPLACE_TENANT_ID", tenant)
    response = await http_client.get("/auth/enrollment/marketplace")
    assert response.status_code == 200
    assert response.json() == {"tenant_id": str(tenant)}


@pytest.mark.asyncio
@respx.mock
async def test_introspection_rejects_unconfirmed_interactive_clients(
    http_client, monkeypatch
):
    monkeypatch.setattr(api_config.settings, "auth_token_validation_mode", "introspection")
    introspect_url = "http://keycloak.test/realms/demo/protocol/openid-connect/token/introspect"
    respx.post(introspect_url).mock(
        side_effect=[
            Response(200, json={"active": True, "sub": "person", "azp": "hypermesh-native", "account_type": "human"}),
            Response(200, json={"active": True, "sub": "person", "client_id": "controlplane-mobile"}),
            Response(200, json={"active": True, "sub": "person", "azp": "controlplane-device", "terms_and_conditions": 0}),
            Response(200, json={"active": True, "sub": "person", "azp": "controlplane-frontend", "terms_and_conditions": 1761900000}),
            Response(200, json={"active": True, "sub": "renter", "client_id": "controlplane-mobile", "account_type": "service"}),
        ]
    )
    for _ in range(3):
        denied = await http_client.get("/auth/me", headers={"Authorization": "Bearer opaque-token"})
        assert denied.status_code == 401
    for _ in range(2):
        accepted = await http_client.get("/auth/me", headers={"Authorization": "Bearer opaque-token"})
        assert accepted.status_code == 200


@pytest.mark.asyncio
@respx.mock
async def test_introspection_rejects_clients_outside_the_allowlist(http_client, monkeypatch):
    monkeypatch.setattr(api_config.settings, "auth_token_validation_mode", "introspection")
    introspect_url = "http://keycloak.test/realms/demo/protocol/openid-connect/token/introspect"
    respx.post(introspect_url).mock(
        return_value=Response(
            200,
            json={
                "active": True,
                "sub": "person",
                "client_id": "s3rch-web",
                "azp": "s3rch-web",
            },
        )
    )
    denied = await http_client.get("/auth/me", headers={"Authorization": "Bearer opaque-token"})
    assert denied.status_code == 401



@pytest.mark.asyncio
@respx.mock
async def test_contact_approval_cannot_recover_login_or_tenant_session(http_client, event_sink, tenant_uuid):
    # The issuer owns refresh tokens. A verification result or OTP is not one.
    issuer = respx.post("http://keycloak.test/realms/demo/protocol/openid-connect/token").mock(
        return_value=Response(400, json={"error": "invalid_grant"})
    )
    contact = {"purpose": "onboarding", "decision": "allow", "phone_status": "verified"}
    for credential in ("123456", str(uuid.uuid4())):
        refreshed = await http_client.post("/auth/refresh", json={"refresh_token": credential, **contact})
        assert refreshed.status_code == 401 and "access_token" not in refreshed.json()
        switched = await http_client.post("/auth/switch-tenant", json={"tenant_id": str(tenant_uuid), **contact})
        assert switched.status_code == 401 and "access_token" not in switched.json()
    assert issuer.call_count == 2
    assert not any(event["event_type"] == AUTH_TOKEN_ISSUED_V1 for event in event_sink)
