"""Test-plane smoke session. No live GitHub and no database."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from api.infrastructure.persistence.db_session import reset_db_session, set_db_session
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt
from auth_service.enrollment import EnrollmentError, EnrollmentGrantResult
from auth_service.smoke_oidc import (
    SMOKE_EMAIL,
    SMOKE_OIDC_ENVIRONMENT,
    SMOKE_OIDC_REPOSITORY,
    SMOKE_OIDC_SUBJECT,
    SmokeOidcRejected,
    require_smoke_oidc_claims,
    smoke_oidc_enabled,
    verify_github_actions_oidc,
)

USER_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")


class _Member:
    id = USER_ID


def _claims(**overrides: str) -> dict[str, str]:
    body = {
        "repository": SMOKE_OIDC_REPOSITORY,
        "environment": SMOKE_OIDC_ENVIRONMENT,
        "sub": SMOKE_OIDC_SUBJECT,
    }
    body.update(overrides)
    return body


def test_flag_overrides_issuer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "KEYCLOAK_ISSUER", "https://auth.test.hyperme.sh/realms/controlplane"
    )
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "0")
    assert smoke_oidc_enabled() is False
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "1")
    monkeypatch.setenv("KEYCLOAK_ISSUER", "https://auth.hyperme.sh/realms/controlplane")
    assert smoke_oidc_enabled() is True


def test_test_issuer_enables_and_prod_issuer_does_not(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HYPERMESH_SMOKE_OIDC", raising=False)
    monkeypatch.setenv(
        "KEYCLOAK_ISSUER", "https://auth.test.hyperme.sh/realms/controlplane"
    )
    assert smoke_oidc_enabled() is True
    monkeypatch.setenv("KEYCLOAK_ISSUER", "https://auth.hyperme.sh/realms/controlplane")
    assert smoke_oidc_enabled() is False


def test_claims_reject_a_pull_request_subject() -> None:
    require_smoke_oidc_claims(_claims())
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(
            _claims(sub="repo:FyberLabs/panopticon:pull_request")
        )
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims(repository="other/panopticon"))
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims(environment="production"))


def test_verify_rejects_a_non_jwt() -> None:
    with pytest.raises(SmokeOidcRejected):
        verify_github_actions_oidc("not-a-jwt")


@pytest.mark.asyncio
async def test_session_is_404_when_disabled(app, http_client, monkeypatch) -> None:
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "0")
    response = await http_client.post(
        "/auth/hypermesh-smoke/session",
        headers={"Authorization": "Bearer not-a-jwt"},
        json={},
    )
    assert response.status_code == 404
    assert "not-a-jwt" not in response.text


@pytest.mark.asyncio
async def test_session_rejects_bad_oidc_without_echoing_the_token(
    app, http_client, monkeypatch
) -> None:
    del app
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "1")
    secret = "smoke-token-must-not-appear-in-the-body"
    response = await http_client.post(
        "/auth/hypermesh-smoke/session",
        headers={"Authorization": f"Bearer {secret}"},
        json={},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "GitHub OIDC token rejected"
    assert secret not in response.text


@pytest.mark.asyncio
async def test_session_mints_renter_tenant_jwt(
    app, http_client, monkeypatch, event_sink
) -> None:
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "1")
    token_ctx = set_db_session(object())  # type: ignore[arg-type]
    try:
        with (
            patch(
                "auth_service.routes.verify_github_actions_oidc",
                return_value=_claims(),
            ),
            patch(
                "auth_service.routes.grant_held_roles",
                new=AsyncMock(
                    return_value=EnrollmentGrantResult(
                        granted=("renter",),
                        refused=(),
                        wallet_address=None,
                    )
                ),
            ),
            patch(
                "api.infrastructure.persistence.tenant_membership.get_tenant_membership_row",
                new=AsyncMock(return_value=_Member()),
            ),
        ):
            response = await http_client.post(
                "/auth/hypermesh-smoke/session",
                headers={"Authorization": "Bearer header.payload.sig"},
                json={},
            )
    finally:
        reset_db_session(token_ctx)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tenant_id"] == str(MARKETPLACE_TENANT_ID)
    assert body["user_id"] == str(USER_ID)
    assert body["expires_in"] == 900
    claims = try_decode_tenant_session_jwt(body["access_token"])
    assert claims is not None
    assert claims["sub"] == str(USER_ID)
    assert claims["email"] == SMOKE_EMAIL
    assert claims["panopticon_auth"] == "tenant_session"
    assert "renter" in claims["realm_access"]["roles"]
    assert "renter" in claims["groups"]
    assert event_sink[-1]["payload"]["grant_type"] == "hypermesh_smoke"
    assert "header.payload.sig" not in response.text


@pytest.mark.asyncio
async def test_session_enrollment_failure_is_generic(
    app, http_client, monkeypatch
) -> None:
    del app
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "1")
    token_ctx = set_db_session(object())  # type: ignore[arg-type]
    try:
        with (
            patch(
                "auth_service.routes.verify_github_actions_oidc",
                return_value=_claims(),
            ),
            patch(
                "auth_service.routes.grant_held_roles",
                new=AsyncMock(side_effect=EnrollmentError("db password=super-secret")),
            ),
        ):
            response = await http_client.post(
                "/auth/hypermesh-smoke/session",
                headers={"Authorization": "Bearer header.payload.sig"},
                json={},
            )
    finally:
        reset_db_session(token_ctx)
    assert response.status_code == 400
    assert response.json()["detail"] == "smoke renter enrollment failed"
    assert "super-secret" not in response.text
