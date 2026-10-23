"""Payout authority must never inherit compatibility MFA or refresh timestamps."""

import copy
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from auth_service.connect_session import SessionDenied, verified_facts
from controlplane_api.config import settings

TENANT = str(uuid.uuid4())


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
    assert response.json()["source"] == "auth_connect_session_v1"
