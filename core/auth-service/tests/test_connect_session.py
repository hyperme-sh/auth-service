"""Payout authority must never inherit compatibility MFA or refresh timestamps."""

import copy
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from auth_service.connect_session import SessionDenied, verified_facts
from controlplane_api.config import settings

TENANT = str(uuid.uuid4())


@pytest.fixture(autouse=True)
def confidential_client(monkeypatch):
    monkeypatch.setenv(
        "AUTH_CONNECT_INTROSPECTION_CLIENT_ID", "auth-connect-introspection"
    )
    monkeypatch.setenv(
        "AUTH_CONNECT_INTROSPECTION_CLIENT_SECRET", "test-private-introspection-secret"
    )


def claims():
    return (
        {
            "panopticon_auth": "tenant_session",
            "azp": "controlplane-frontend",
            "sub": "owner",
            "tenant_id": TENANT,
        },
        {
            "azp": "controlplane-frontend",
            "iss": settings.keycloak_issuer.rstrip("/"),
            "sub": "owner",
            "sid": "browser-session",
            "exp": 2000,
            "iat": 1000,
            "auth_time": 900,
            "acr": "2",
            "amr": ["pwd", "otp"],
        },
        {"active": True, "sub": "owner", "client_id": "controlplane-frontend"},
    )


def test_verified_factor_uses_original_authentication_not_refresh():
    tenant, origin, active = claims()
    facts = verified_facts(tenant, origin, active, now=1100)
    assert facts["second_factor_at"] == "1970-01-01T00:15:00+00:00"
    before = facts["session_ref"]
    origin["iat"] = 1090
    assert verified_facts(tenant, origin, active, now=1100)["session_ref"] == before
    assert "browser-session" not in str(facts)


@pytest.mark.parametrize(
    "part,key,value",
    [
        (0, "panopticon_auth", "api_key"),
        (0, "smoke_session", True),
        (0, "azp", "controlplane-m2m"),
        (0, "sub", "other"),
        (1, "iss", "https://other.example"),
        (1, "azp", "controlplane-m2m"),
        (1, "sid", None),
        (1, "exp", True),
        (1, "iat", "1000"),
        (1, "auth_time", 1101),
        (1, "auth_time", True),
        (1, "exp", 1100),
        (2, "active", 1),
        (2, "active", False),
        (2, "sub", "other"),
        (2, "client_id", "controlplane-m2m"),
        (2, "sid", "other"),
    ],
)
def test_wrong_or_revoked_credentials_denied(part, key, value):
    args = copy.deepcopy(claims())
    args[part][key] = value
    with pytest.raises(SessionDenied):
        verified_facts(*args, now=1100)


@pytest.mark.parametrize(
    "changes",
    [
        {"amr": ["mfa"]},
        {"amr": ["pwd", "not-otp"]},
        {"amr": ["webauthn"]},
        {"amr": "pwd otp"},
        {"acr": 2},
        {"acr": "1"},
        {"amr": ["otp"]},
    ],
)
def test_unproved_mfa_never_upgraded(changes):
    tenant, origin, active = claims()
    origin.update(changes)
    assert verified_facts(tenant, origin, active, now=1100)["second_factor_at"] is None


@pytest.mark.asyncio
async def test_endpoint_ignores_raw_mfa_headers_and_never_echoes_credentials(
    http_client,
):
    response = await http_client.get(
        "/auth/connect-session-context",
        headers={
            "Authorization": "Bearer private-invalid-tenant",
            "X-Auth-Session-Token": "private-original",
            "X-Auth-Time": "9999999999",
            "X-AMR": "otp",
            "X-Tenant-ID": TENANT,
        },
    )
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"
    assert "private-" not in response.text


@pytest.mark.asyncio
async def test_endpoint_rechecks_exact_member_and_active_issuer(http_client):
    tenant, origin, active = claims()
    # Current time is intentionally supplied by the signed origin, not headers.
    import time

    stamp = int(time.time())
    origin.update(exp=stamp + 300, iat=stamp, auth_time=stamp - 30)
    validator = type("Validator", (), {"validate": AsyncMock(return_value=origin)})()
    with (
        patch(
            "auth_service.connect_session.try_decode_tenant_session_jwt",
            return_value=tenant,
        ),
        patch(
            "auth_service.connect_session.get_keycloak_jwt_validator",
            return_value=validator,
        ),
        patch(
            "auth_service.connect_session.introspect_access_token",
            AsyncMock(return_value=active),
        ),
        patch(
            "auth_service.connect_session.current_member",
            AsyncMock(return_value=str(uuid.uuid4())),
        ) as member,
    ):
        response = await http_client.get(
            "/auth/connect-session-context",
            headers={
                "Authorization": "Bearer tenant",
                "X-Auth-Session-Token": "original",
                "X-Tenant-ID": TENANT,
            },
        )
    assert response.status_code == 200
    member.assert_awaited_once_with(uuid.UUID(TENANT), "owner")
    assert response.json()["source"] == "auth_connect_session_v2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "upstream,expected",
    [
        (ValueError("PRIVATE_BROKEN_JSON"), 503),
        (None, 503),
        ([], 503),
        ({}, 503),
        ({"active": "true"}, 503),
        ({"active": 1}, 503),
        ({"active": True}, 503),
        ({"active": True, "sub": "owner", "client_id": None}, 503),
        (
            {
                "active": True,
                "sub": "owner",
                "client_id": "controlplane-frontend",
                "sid": [],
            },
            503,
        ),
        ({"active": False}, 403),
    ],
)
async def test_introspection_outages_are_distinct_from_explicit_denial(
    http_client, upstream, expected
):
    import time

    tenant, origin, _ = claims()
    now = int(time.time())
    origin.update(exp=now + 300, iat=now, auth_time=now - 30)
    validator = type("Validator", (), {"validate": AsyncMock(return_value=origin)})()
    introspection = (
        AsyncMock(side_effect=upstream)
        if isinstance(upstream, Exception)
        else AsyncMock(return_value=upstream)
    )
    with (
        patch(
            "auth_service.connect_session.try_decode_tenant_session_jwt",
            return_value=tenant,
        ),
        patch(
            "auth_service.connect_session.get_keycloak_jwt_validator",
            return_value=validator,
        ),
        patch("auth_service.connect_session.introspect_access_token", introspection),
        patch("auth_service.connect_session.current_member", AsyncMock()) as member,
    ):
        response = await http_client.get(
            "/auth/connect-session-context",
            headers={
                "Authorization": "Bearer private-tenant",
                "X-Auth-Session-Token": "private-original",
                "X-Tenant-ID": TENANT,
            },
        )
    assert response.status_code == expected
    assert response.headers["cache-control"] == "no-store"
    assert "PRIVATE_" not in response.text and "private-" not in response.text
    member.assert_not_awaited()


@pytest.mark.asyncio
async def test_introspection_uses_confidential_caller_but_observes_browser_client():
    from urllib.parse import parse_qs

    import httpx
    from auth_service.connect_session import confidential_introspection_credentials
    from auth_service.keycloak_oidc import introspect_access_token

    caller, secret = confidential_introspection_credentials()

    def handler(request):
        form = parse_qs(request.content.decode())
        assert form["client_id"] == ["auth-connect-introspection"]
        assert form["client_secret"] == ["test-private-introspection-secret"]
        assert form["token"] == ["original-browser-token"]
        return httpx.Response(
            200,
            json={"active": True, "sub": "owner", "client_id": "controlplane-frontend"},
        )

    with patch(
        "auth_service.keycloak_oidc._issuer_base",
        return_value="https://issuer.test/realms/test",
    ):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await introspect_access_token(
                "original-browser-token",
                client=client,
                client_id=caller,
                client_secret=secret,
            )
    assert result["client_id"] == "controlplane-frontend"


@pytest.mark.parametrize(
    "client_id,secret",
    [
        (None, "secret"),
        ("auth-connect-introspection", None),
        ("controlplane-frontend", "secret"),
    ],
)
def test_missing_or_public_introspection_configuration_refuses(
    monkeypatch, client_id, secret
):
    from auth_service.connect_session import (
        SessionUnavailable,
        confidential_introspection_credentials,
    )

    monkeypatch.delenv("AUTH_CONNECT_INTROSPECTION_CLIENT_ID", raising=False)
    monkeypatch.delenv("AUTH_CONNECT_INTROSPECTION_CLIENT_SECRET", raising=False)
    if client_id is not None:
        monkeypatch.setenv("AUTH_CONNECT_INTROSPECTION_CLIENT_ID", client_id)
    if secret is not None:
        monkeypatch.setenv("AUTH_CONNECT_INTROSPECTION_CLIENT_SECRET", secret)
    with pytest.raises(SessionUnavailable):
        confidential_introspection_credentials()


@pytest.mark.asyncio
async def test_only_verified_membership_revocation_has_durable_revocation_code(
    http_client,
):
    import time

    from auth_service.connect_session import MembershipRevoked

    tenant, origin, active = claims()
    now = int(time.time())
    origin.update(exp=now + 300, iat=now, auth_time=now - 30)
    validator = type("Validator", (), {"validate": AsyncMock(return_value=origin)})()
    with (
        patch(
            "auth_service.connect_session.try_decode_tenant_session_jwt",
            return_value=tenant,
        ),
        patch(
            "auth_service.connect_session.get_keycloak_jwt_validator",
            return_value=validator,
        ),
        patch(
            "auth_service.connect_session.introspect_access_token",
            AsyncMock(return_value=active),
        ),
        patch(
            "auth_service.connect_session.current_member",
            AsyncMock(side_effect=MembershipRevoked()),
        ),
    ):
        response = await http_client.get(
            "/auth/connect-session-context",
            headers={
                "Authorization": "Bearer tenant",
                "X-Auth-Session-Token": "original",
                "X-Tenant-ID": TENANT,
            },
        )
    assert response.status_code == 403
    assert response.json()["code"] == "membership_revoked"
    assert response.headers["cache-control"] == "no-store"


def test_checked_in_introspection_client_is_confidential_and_has_no_login_flows():
    import json
    from pathlib import Path

    realm = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "infra/keycloak/import/controlplane-realm.json"
        ).read_text()
    )
    client = next(
        c for c in realm["clients"] if c["clientId"] == "auth-connect-introspection"
    )
    assert client["publicClient"] is False
    assert client["clientAuthenticatorType"] == "client-secret"
    assert all(
        client[k] is False
        for k in (
            "standardFlowEnabled",
            "implicitFlowEnabled",
            "directAccessGrantsEnabled",
            "serviceAccountsEnabled",
            "fullScopeAllowed",
        )
    )
    assert (
        "secret" not in client
    )  # Keycloak generates it; no reusable secret is checked in.


def test_absolute_connect_session_age_cannot_be_extended_by_refresh():
    from auth_service.connect_session import MAX_CONNECT_SESSION_AGE_SECONDS

    tenant, origin, active = claims()
    now = origin["auth_time"] + MAX_CONNECT_SESSION_AGE_SECONDS
    origin.update(iat=now - 1, exp=now + 300)
    with pytest.raises(SessionDenied):
        verified_facts(tenant, origin, active, now=now)
    assert verified_facts(tenant, origin, active, now=now - 1)["session_ref"]


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [True, False])
async def test_end_context_authenticates_original_session_without_any_tenant_or_host(
    http_client, valid
):
    import time

    _, origin, active = claims()
    stamp = int(time.time())
    origin.update(exp=stamp + 300, iat=stamp, auth_time=stamp - 30)
    if not valid:
        active = {"active": False}
    validator = type("Validator", (), {"validate": AsyncMock(return_value=origin)})()
    with (
        patch(
            "auth_service.connect_session.get_keycloak_jwt_validator",
            return_value=validator,
        ),
        patch(
            "auth_service.connect_session.introspect_access_token",
            AsyncMock(return_value=active),
        ),
        patch(
            "auth_service.connect_session.current_member",
            AsyncMock(side_effect=AssertionError("must not read tenant membership")),
        ) as member,
    ):
        response = await http_client.get(
            "/auth/connect-session-end-context",
            headers={"X-Auth-Session-Token": "original"},
        )
    assert response.status_code == (200 if valid else 403)
    member.assert_not_called()
    if valid:
        body = response.json()
        assert (
            body["source"] == "auth_connect_session_end_v1"
            and len(body["session_ref"]) == 64
        )
        assert not {"tenant_id", "member_id", "second_factor_at"}.intersection(body)
        assert response.headers["cache-control"] == "no-store"
