"""OIDC domain plus user/group maps assign operator and owner claims."""

from __future__ import annotations

import pytest

from api.core import config as api_config
from api.domain.operator.population import (
    SEEDED_TEST_ADMIN_EMAIL,
    SEEDED_TEST_ADMIN_OPERATOR_CLAIMS,
    mapped_oidc_claims,
    tenant_session_permissions,
)
from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt
from auth_service.tenant_switch import TenantSwitchGrant

FYBER = "fyberlabs.com"
SUPPORT_GROUP = "operator-support"
PROGRAM_GROUP = "operator-program"
SUPPORT_CLAIMS = "operator:console|operator:support"
PROGRAM_CLAIMS = "operator:program|operator:resolve"
GROUP_MAP = (
    f"{SUPPORT_GROUP}={SUPPORT_CLAIMS};"
    f"{PROGRAM_GROUP}={PROGRAM_CLAIMS}"
)
USER_MAP = f"owner@{FYBER}=org:own"


def _configure(monkeypatch, *, domain: str, group_map: str = GROUP_MAP, user_map: str = USER_MAP) -> None:
    monkeypatch.setattr(api_config.settings, "operator_oidc_domain", domain)
    monkeypatch.setattr(api_config.settings, "operator_oidc_group_map", group_map)
    monkeypatch.setattr(api_config.settings, "operator_oidc_user_map", user_map)


def test_seeded_admin_has_four_operator_claims_and_not_org_owner() -> None:
    assert SEEDED_TEST_ADMIN_EMAIL == "admin@test.hyperme.sh"
    assert SEEDED_TEST_ADMIN_OPERATOR_CLAIMS == (
        "operator:console",
        "operator:support",
        "operator:program",
        "operator:resolve",
    )
    perms = tenant_session_permissions(
        ("host:manage_tenants",),
        email=SEEDED_TEST_ADMIN_EMAIL,
        groups=(),
    )
    for claim in SEEDED_TEST_ADMIN_OPERATOR_CLAIMS:
        assert claim in perms
    assert "org:own" not in perms
    assert "org:manage" not in perms


def test_mapped_domain_group_receives_mapped_claims(monkeypatch) -> None:
    _configure(monkeypatch, domain=FYBER)
    support = mapped_oidc_claims(
        f"ada@{FYBER}",
        groups=[f"/{SUPPORT_GROUP}"],
        hosted_domains=(),
    )
    assert support == ("operator:console", "operator:support")
    program = mapped_oidc_claims(
        f"bea@{FYBER}",
        groups=[PROGRAM_GROUP],
        hosted_domains=[FYBER],
    )
    assert program == ("operator:program", "operator:resolve")
    assert "operator:support" not in program
    owner = mapped_oidc_claims(f"owner@{FYBER}", groups=(), hosted_domains=())
    assert owner == ("org:own",)
    assert "operator:support" not in owner


def test_hosted_domain_counts_when_email_domain_differs(monkeypatch) -> None:
    _configure(monkeypatch, domain=FYBER)
    claims = mapped_oidc_claims(
        "ada@gmail.com",
        groups=[SUPPORT_GROUP],
        hosted_domains=(FYBER,),
    )
    assert claims == ("operator:console", "operator:support")


def test_user_outside_domain_does_not_receive_operator_claims(monkeypatch) -> None:
    _configure(monkeypatch, domain=FYBER)
    outside = mapped_oidc_claims(
        "ada@other.example",
        groups=[f"/{SUPPORT_GROUP}", PROGRAM_GROUP],
        hosted_domains=("other.example",),
    )
    assert outside == ()
    claimed_owner = mapped_oidc_claims(
        "owner@other.example",
        groups=(),
        hosted_domains=(),
    )
    assert claimed_owner == ()


def test_second_domain_replaces_fyberlabs(monkeypatch) -> None:
    _configure(monkeypatch, domain="other.example", user_map="owner@other.example=org:own")
    fyber = mapped_oidc_claims(
        f"ada@{FYBER}",
        groups=[SUPPORT_GROUP],
        hosted_domains=(FYBER,),
    )
    assert fyber == ()
    other = mapped_oidc_claims(
        "ada@other.example",
        groups=[f"/{PROGRAM_GROUP}"],
        hosted_domains=(),
    )
    assert other == ("operator:program", "operator:resolve")
    owner = mapped_oidc_claims("owner@other.example", groups=())
    assert owner == ("org:own",)


@pytest.mark.asyncio
async def test_switch_tenant_jwt_carries_mapped_group_claims(
    app, http_client, tenant_uuid, monkeypatch
):
    from unittest.mock import patch

    from auth_service import deps

    _configure(monkeypatch, domain=FYBER)

    async def fake_claims() -> dict:
        return {
            "sub": "ada",
            "email": f"ada@{FYBER}",
            "hd": FYBER,
            "azp": "controlplane-frontend",
            "realm_access": {"roles": ["user"]},
            "groups": [f"/{SUPPORT_GROUP}"],
            "scope": "openid",
        }

    async def allow(*_a, **_k):
        return TenantSwitchGrant(role_name="user", permissions=("user:view_only",))

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
        assert "operator:console" in claims["permissions"]
        assert "operator:support" in claims["permissions"]
        assert "operator:program" not in claims["permissions"]
        assert "operator:resolve" not in claims["permissions"]
        assert "org:own" not in claims["permissions"]
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)
