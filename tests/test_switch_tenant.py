from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from api.core import config as api_config
from api.domain.operator.population import SEEDED_TEST_ADMIN_OPERATOR_CLAIMS
from api.infrastructure.security.api_key_exchange_jwt import try_decode_api_key_session_jwt
from api.infrastructure.security.tenant_session_jwt import (
    mint_tenant_session_jwt,
    try_decode_tenant_session_jwt,
)
from auth_service.schemas import AuthMeResponse
from auth_service.tenant_switch import (
    TenantSwitchGrant,
    _email_norm,
    _role_has_host_manage,
    authorize_tenant_switch,
)


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
        assert claims["azp"] == "controlplane-m2m"
        assert claims["tenant_id"] == str(tenant_uuid)
        assert claims["https://spanopticon.dev/tenant_id"] == str(tenant_uuid)
        assert claims["spanopticon_auth"] == "tenant_session"
        assert "admin" in claims["realm_access"]["roles"]
        assert claims.get("purpose") is None
        assert try_decode_api_key_session_jwt(token) is None
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


@pytest.mark.asyncio
async def test_switch_tenant_seeded_admin_jwt_carries_operator_claims(
    app, http_client, tenant_uuid, monkeypatch
):
    """Pan-test admin gets the four operator claims. Not org:own or org:manage."""
    from auth_service import deps

    monkeypatch.setattr(api_config.settings, "operator_oidc_domain", "")
    monkeypatch.setattr(api_config.settings, "operator_oidc_group_map", "")
    monkeypatch.setattr(api_config.settings, "operator_oidc_user_map", "")

    async def fake_claims() -> dict:
        return {
            "sub": "admin-sub",
            "email": "admin@test.hyperme.sh",
            "azp": "controlplane-frontend",
            "realm_access": {"roles": ["admin"]},
            "groups": [],
            "scope": "openid",
        }

    async def allow(*_a, **_k):
        return TenantSwitchGrant(
            role_name="admin",
            permissions=("host:manage_tenants", *SEEDED_TEST_ADMIN_OPERATOR_CLAIMS),
        )

    app.dependency_overrides[deps.get_access_token_claims] = fake_claims
    try:
        with patch("auth_service.routes.authorize_tenant_switch", new=allow):
            r = await http_client.post(
                "/auth/switch-tenant",
                headers={"Authorization": "Bearer fake.jwt"},
                json={"tenant_id": str(tenant_uuid)},
            )
        assert r.status_code == 200, r.text
        claims = try_decode_tenant_session_jwt(r.json()["access_token"])
        assert claims is not None
        for claim in SEEDED_TEST_ADMIN_OPERATOR_CLAIMS:
            assert claim in claims["permissions"]
        assert "org:own" not in claims["permissions"]
        assert "org:manage" not in claims["permissions"]
        assert "host:manage_tenants" in claims["permissions"]
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


@pytest.mark.asyncio
async def test_switch_tenant_other_admin_does_not_inherit_seed_operator_claims(
    app, http_client, tenant_uuid, monkeypatch
):
    from auth_service import deps

    monkeypatch.setattr(api_config.settings, "operator_oidc_domain", "")
    monkeypatch.setattr(api_config.settings, "operator_oidc_group_map", "")
    monkeypatch.setattr(api_config.settings, "operator_oidc_user_map", "")

    async def fake_claims() -> dict:
        return {
            "sub": "other-admin",
            "email": "org-admin@example.com",
            "azp": "controlplane-frontend",
            "realm_access": {"roles": ["admin"]},
            "groups": [],
            "scope": "openid",
        }

    async def allow(*_a, **_k):
        return TenantSwitchGrant(
            role_name="admin",
            permissions=("host:manage_tenants", "full:access"),
        )

    app.dependency_overrides[deps.get_access_token_claims] = fake_claims
    try:
        with patch("auth_service.routes.authorize_tenant_switch", new=allow):
            r = await http_client.post(
                "/auth/switch-tenant",
                headers={"Authorization": "Bearer fake.jwt"},
                json={"tenant_id": str(tenant_uuid)},
            )
        assert r.status_code == 200, r.text
        claims = try_decode_tenant_session_jwt(r.json()["access_token"])
        assert claims is not None
        for claim in SEEDED_TEST_ADMIN_OPERATOR_CLAIMS:
            assert claim not in claims["permissions"]
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


class _Exec:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeSession:
    def __init__(self, values: list):
        self._values = list(values)

    async def execute(self, _stmt, _params=None):
        if not self._values:
            raise AssertionError("unexpected extra SQL")
        return _Exec(self._values.pop(0))


def test_email_norm_and_host_perm_helpers():
    assert _email_norm(AuthMeResponse(sub="s", email="Chris@FyberLabs.com")) == (
        "chris@fyberlabs.com"
    )
    assert _email_norm(AuthMeResponse(sub="s", email=None)) is None
    host_role = type("R", (), {"permissions": ["host:manage_tenants"]})()
    guest_role = type("R", (), {"permissions": ["user:view_only"]})()
    assert _role_has_host_manage(host_role) is True
    assert _role_has_host_manage(guest_role) is False
    assert _role_has_host_manage(None) is False


@pytest.mark.asyncio
async def test_authorize_member_and_host_and_unknown(tenant_uuid):
    me = AuthMeResponse(sub="kc-sub", email="chris@fyberlabs.com")
    member = type(
        "U",
        (),
        {"role_id": uuid.uuid4(), "tenant_id": tenant_uuid, "is_active": True, "keycloak_sub": "kc-sub"},
    )()
    tenant_admin = type("R", (), {"name": "admin", "permissions": []})()
    platform = type("U", (), {"role_id": uuid.uuid4(), "tenant_id": None, "is_active": True, "keycloak_sub": "kc-sub"})()
    host_role = type(
        "R",
        (),
        {"name": "admin", "permissions": ["host:manage_tenants"]},
    )()
    guest_role = type(
        "R",
        (),
        {"name": "guest", "permissions": ["user:view_only"]},
    )()

    with patch(
        "auth_service.tenant_switch.set_current_tenant_id_guc",
        new=AsyncMock(),
    ):
        granted = await authorize_tenant_switch(
            me, tenant_uuid, session=_FakeSession([tenant_uuid, member, tenant_admin])
        )
        assert granted == TenantSwitchGrant(role_name="admin", permissions=())

        host = await authorize_tenant_switch(
            me,
            tenant_uuid,
            session=_FakeSession([tenant_uuid, None, None, platform, host_role]),
        )
        assert host == TenantSwitchGrant(
            role_name="admin",
            permissions=("host:manage_tenants",),
        )

        denied = await authorize_tenant_switch(
            me,
            tenant_uuid,
            session=_FakeSession([tenant_uuid, None, None, platform, guest_role]),
        )
        assert denied is None

        missing = await authorize_tenant_switch(
            me, tenant_uuid, session=_FakeSession([None])
        )
        assert missing is None


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
