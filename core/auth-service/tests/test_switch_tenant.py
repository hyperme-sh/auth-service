from __future__ import annotations

from unittest.mock import patch

import pytest

from api.infrastructure.security.api_key_exchange_jwt import try_decode_api_key_session_jwt
from api.infrastructure.security.tenant_session_jwt import (
    mint_tenant_session_jwt,
    try_decode_tenant_session_jwt,
)
from auth_service.tenant_switch import TenantSwitchGrant


@pytest.mark.asyncio
async def test_switch_tenant_mints_jwt_with_tenant_claim(
    app, http_client, tenant_uuid
):
    from auth_service import deps

    async def fake_claims() -> dict:
        return {
            "sub": "sub-1",
            "email": "chris@fyberlabs.com",
            "azp": "controlplane-m2m",
            "realm_access": {"roles": ["offline_access"]},
            "scope": "openid",
        }

    async def allow(*_a, **_k):
        return TenantSwitchGrant(role_name="admin")

    app.dependency_overrides[deps.get_access_token_claims] = fake_claims
    try:
        with patch("auth_service.routes.authorize_tenant_switch", new=allow):
            r = await http_client.post(
                "/auth/switch-tenant",
                headers={
                    "Authorization": "Bearer fake.jwt",
                    "X-Tenant-ID": str(tenant_uuid),
                },
                json={"tenant_id": str(tenant_uuid)},
            )
        assert r.status_code == 200, r.text
        token = r.json()["access_token"]
        claims = try_decode_tenant_session_jwt(token)
        assert claims is not None
        assert claims["tenant_id"] == str(tenant_uuid)
        assert claims["https://panopticon.dev/tenant_id"] == str(tenant_uuid)
        assert claims["panopticon_auth"] == "tenant_session"
        assert "admin" in claims["realm_access"]["roles"]
        assert claims.get("purpose") is None
        assert try_decode_api_key_session_jwt(token) is None
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


@pytest.mark.asyncio
async def test_switch_tenant_header_mismatch_rejected(app, http_client, tenant_uuid):
    from auth_service import deps

    other = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"

    async def fake_claims() -> dict:
        return {
            "sub": "sub-1",
            "email": "chris@fyberlabs.com",
            "realm_access": {"roles": []},
            "scope": "openid",
        }

    app.dependency_overrides[deps.get_access_token_claims] = fake_claims
    try:
        r = await http_client.post(
            "/auth/switch-tenant",
            headers={
                "Authorization": "Bearer fake.jwt",
                "X-Tenant-ID": other,
            },
            json={"tenant_id": str(tenant_uuid)},
        )
        assert r.status_code == 403
        assert "X-Tenant-ID" in r.json()["detail"]
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


@pytest.mark.asyncio
async def test_switch_tenant_refuses_without_membership(app, http_client, tenant_uuid):
    from auth_service import deps

    async def fake_claims() -> dict:
        return {
            "sub": "sub-1",
            "email": "chris@fyberlabs.com",
            "realm_access": {"roles": []},
            "scope": "openid",
        }

    async def deny(*_a, **_k):
        return None

    app.dependency_overrides[deps.get_access_token_claims] = fake_claims
    try:
        with patch("auth_service.routes.authorize_tenant_switch", new=deny):
            r = await http_client.post(
                "/auth/switch-tenant",
                headers={"Authorization": "Bearer fake.jwt"},
                json={"tenant_id": str(tenant_uuid)},
            )
        assert r.status_code == 403
        assert "member" in r.json()["error"].lower()
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


@pytest.mark.asyncio
async def test_switched_token_satisfies_get_current_tenant(http_client, tenant_uuid):
    token = mint_tenant_session_jwt(
        claims={
            "sub": "sub-1",
            "email": "chris@fyberlabs.com",
            "realm_access": {"roles": ["admin"]},
            "scope": "openid",
        },
        tenant_id=tenant_uuid,
        extra_roles=["admin"],
    )
    r = await http_client.get(
        "/auth/tenant",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["tenant_id"] == str(tenant_uuid)


@pytest.mark.asyncio
async def test_header_only_still_missing_tenant_context(app, http_client, tenant_uuid):
    from auth_service import deps

    async def claims_no_tenant() -> dict:
        return {
            "sub": "x",
            "email": "chris@fyberlabs.com",
            "realm_access": {"roles": ["admin"]},
            "scope": "openid",
        }

    app.dependency_overrides[deps.get_access_token_claims] = claims_no_tenant
    try:
        r = await http_client.get(
            "/auth/tenant",
            headers={
                "Authorization": "Bearer t",
                "X-Tenant-ID": str(tenant_uuid),
            },
        )
        assert r.status_code == 403
        assert "tenant context" in r.json()["error"].lower()
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)
