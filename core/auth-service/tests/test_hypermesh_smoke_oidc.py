"""Test-plane smoke session. No live GitHub and no database."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError

from api.infrastructure.persistence.db_session import reset_db_session, set_db_session
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt
from auth_service.enrollment import EnrollmentError, EnrollmentGrantResult
from auth_service.smoke_oidc import (
    SMOKE_EMAIL,
    SMOKE_OIDC_AUDIENCE,
    SMOKE_OIDC_ENVIRONMENT,
    SMOKE_OIDC_REPOSITORY,
    SMOKE_OIDC_REF,
    SMOKE_OIDC_SUBJECT,
    SMOKE_WORKFLOW_PATH,
    SmokeOidcMisconfigured,
    SmokeOidcRejected,
    SmokeOidcUnavailable,
    assert_smoke_oidc_plane,
    require_smoke_oidc_claims,
    smoke_oidc_enabled,
    verify_github_actions_oidc,
)

REPO = Path(__file__).resolve().parents[3]
TEST_ISSUER = "https://auth.test.hyperme.sh/realms/controlplane"
PROD_ISSUER = "https://auth.hyperme.sh/realms/controlplane"
JOB_WORKFLOW_REF = f"{SMOKE_WORKFLOW_PATH}@refs/heads/main"

USER_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")


class _Member:
    id = USER_ID


def _claims(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "repository": SMOKE_OIDC_REPOSITORY,
        "environment": SMOKE_OIDC_ENVIRONMENT,
        "sub": SMOKE_OIDC_SUBJECT,
        "job_workflow_ref": JOB_WORKFLOW_REF,
        "ref": SMOKE_OIDC_REF,
        "aud": SMOKE_OIDC_AUDIENCE,
    }
    body.update(overrides)
    return body


def test_flag_defaults_off_even_on_a_test_issuer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HYPERMESH_SMOKE_OIDC", raising=False)
    monkeypatch.setenv("KEYCLOAK_ISSUER", TEST_ISSUER)
    assert smoke_oidc_enabled() is False
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "true")
    assert smoke_oidc_enabled() is False
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "1")
    monkeypatch.setenv("KEYCLOAK_ISSUER", PROD_ISSUER)
    assert smoke_oidc_enabled() is True


def test_startup_refuses_prod_issuer_or_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "1")
    monkeypatch.setenv("KEYCLOAK_ISSUER", PROD_ISSUER)
    monkeypatch.delenv("KEYCLOAK_HOSTNAME", raising=False)
    monkeypatch.delenv("KEYCLOAK_HOSTNAME_PUBLIC", raising=False)
    with pytest.raises(SmokeOidcMisconfigured):
        assert_smoke_oidc_plane()

    monkeypatch.setenv("KEYCLOAK_ISSUER", TEST_ISSUER)
    monkeypatch.setenv("KEYCLOAK_HOSTNAME_PUBLIC", "auth.hyperme.sh")
    with pytest.raises(SmokeOidcMisconfigured):
        assert_smoke_oidc_plane()

    monkeypatch.setenv("KEYCLOAK_HOSTNAME_PUBLIC", "auth.test.hyperme.sh")
    assert_smoke_oidc_plane()


def test_startup_allows_a_prod_issuer_when_the_flag_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HYPERMESH_SMOKE_OIDC", raising=False)
    monkeypatch.setenv("KEYCLOAK_ISSUER", PROD_ISSUER)
    assert_smoke_oidc_plane()


def test_claims_pin_repo_environment_workflow_and_audience() -> None:
    require_smoke_oidc_claims(_claims())
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(
            _claims(sub="repo:FyberLabs/panopticon:pull_request")
        )
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims(repository="other/panopticon"))
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims(environment="production"))
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(
            _claims(
                job_workflow_ref=(
                    "FyberLabs/panopticon/.github/workflows/acr-frontend-test.yml"
                    "@refs/heads/main"
                )
            )
        )
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims(job_workflow_ref=SMOKE_WORKFLOW_PATH))
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(
            _claims(job_workflow_ref=JOB_WORKFLOW_REF, workflow_ref=JOB_WORKFLOW_REF)
            | {"job_workflow_ref": None}
        )
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims(aud="https://github.com/FyberLabs/panopticon"))


def test_claims_reject_feature_branch_and_pull_refs() -> None:
    feature = f"{SMOKE_WORKFLOW_PATH}@refs/heads/cursor/hypermesh-gateway-smoke-853b"
    pull = f"{SMOKE_WORKFLOW_PATH}@refs/pull/202/merge"
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims(job_workflow_ref=feature))
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims(job_workflow_ref=pull))
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(
            _claims(ref="refs/heads/cursor/hypermesh-gateway-smoke-853b")
        )
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims(ref="refs/pull/202/merge"))


def test_verify_rejects_a_non_jwt() -> None:
    with pytest.raises(SmokeOidcRejected):
        verify_github_actions_oidc("not-a-jwt")


def test_verify_reports_jwks_unreachable() -> None:
    class _Down(PyJWKClient):
        def __init__(self) -> None:
            return None

        def get_signing_key_from_jwt(self, token: str):
            raise PyJWKClientConnectionError("no route to token.actions.githubusercontent.com")

    with pytest.raises(SmokeOidcUnavailable):
        verify_github_actions_oidc("header.payload.sig", jwks_client=_Down())


@pytest.mark.asyncio
async def test_session_is_404_when_the_flag_is_unset(app, http_client, monkeypatch) -> None:
    del app
    monkeypatch.delenv("HYPERMESH_SMOKE_OIDC", raising=False)
    monkeypatch.setenv("KEYCLOAK_ISSUER", TEST_ISSUER)
    response = await http_client.post(
        "/auth/hypermesh-smoke/session",
        headers={"Authorization": "Bearer not-a-jwt"},
        json={},
    )
    assert response.status_code == 404
    assert "not-a-jwt" not in response.text
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "true")
    again = await http_client.post("/auth/hypermesh-smoke/session", json={})
    assert again.status_code == 404


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
    assert response.json()["code"] == "github_oidc_rejected"
    assert secret not in response.text


@pytest.mark.parametrize("custom", [False, True])
@pytest.mark.asyncio
async def test_session_mints_renter_tenant_jwt(
    app, http_client, monkeypatch, event_sink, custom
) -> None:
    from api.core.config import settings
    if custom:
        monkeypatch.setattr(settings, "smoke_session_email", "example-smoke@example.test")
        monkeypatch.setattr(settings, "smoke_session_username", "example-smoke")
        monkeypatch.setattr(settings, "smoke_session_claim", "example_smoke")
        monkeypatch.setattr(settings, "smoke_oidc_audience", "example-smoke-client")
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
    assert claims["email"] == settings.smoke_session_email
    assert claims["panopticon_auth"] == "tenant_session"
    assert claims["realm_access"]["roles"] == ["renter"]
    assert claims["groups"] == ["renter"]
    assert claims["permissions"] == []
    assert claims["scope"] == "openid"
    assert claims[settings.smoke_session_claim] is True
    assert claims["smoke_session"] is True
    assert claims["hypermesh_smoke"] is True
    assert claims["email"] == settings.smoke_session_email
    assert "admin" not in claims["realm_access"]["roles"]
    forbidden = ("operator:", "manage:payments", "org:own", "org:manage")
    assert not any(str(item).startswith(forbidden) for item in claims["permissions"])
    assert event_sink[-1]["payload"]["grant_type"] == settings.smoke_session_claim
    assert "header.payload.sig" not in response.text

    # A differently deployed auth process must still refuse tenant switching.
    monkeypatch.setattr(settings, "smoke_session_claim", "different_consumer_marker")
    switched = await http_client.post(
        "/auth/switch-tenant",
        headers={"Authorization": f"Bearer {body['access_token']}"},
        json={"tenant_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
    )
    assert switched.status_code == 403
    assert "switch tenant" in switched.text.lower()


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
    assert response.json()["code"] == "smoke_enrollment_failed"
    assert "super-secret" not in response.text


@pytest.mark.asyncio
async def test_session_unexpected_failure_names_the_exception_class(
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
                new=AsyncMock(side_effect=RuntimeError("db password=super-secret")),
            ),
        ):
            response = await http_client.post(
                "/auth/hypermesh-smoke/session",
                headers={"Authorization": "Bearer header.payload.sig"},
                json={},
            )
    finally:
        reset_db_session(token_ctx)
    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "smoke_session_failed"
    assert body["error"] == "RuntimeError"
    assert "super-secret" not in response.text
    assert "header.payload.sig" not in response.text


def test_vm_overlay_sets_the_flag_only_on_auth_service() -> None:
    overlay = (REPO / "docker-compose.vm.yaml").read_text(encoding="utf-8")
    base = (REPO / "docker-compose.yaml").read_text(encoding="utf-8")
    auth = overlay.split("\n  auth-service:\n", 1)[1].split("\n  user-service:\n", 1)[0]
    assert 'HYPERMESH_SMOKE_OIDC: "1"' in auth
    assert "KEYCLOAK_HOSTNAME_PUBLIC" in auth
    assert "HYPERMESH_SMOKE_OIDC" not in overlay.replace(auth, "", 1)
    assert "HYPERMESH_SMOKE_OIDC" not in base


@pytest.mark.asyncio
async def test_lifespan_refuses_to_start_on_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "1")
    monkeypatch.setenv("KEYCLOAK_ISSUER", PROD_ISSUER)
    monkeypatch.delenv("KEYCLOAK_HOSTNAME", raising=False)
    monkeypatch.delenv("KEYCLOAK_HOSTNAME_PUBLIC", raising=False)
    from asgi_lifespan import LifespanManager

    from auth_service.app import create_app

    application = create_app(test_event_sink=[], enable_db_middleware=False)
    with pytest.raises(SmokeOidcMisconfigured):
        async with LifespanManager(application):
            pass


def test_configured_workflow_is_verified_without_product_defaults(monkeypatch):
    from api.core.config import settings
    changes = {
        "smoke_oidc_audience": "example-smoke", "smoke_oidc_repository": "Example/control",
        "smoke_oidc_environment": "staging", "smoke_oidc_subject": "repo:Example/control:environment:staging",
        "smoke_oidc_workflow_path": "Example/control/.github/workflows/smoke.yml",
        "smoke_oidc_ref": "refs/heads/release",
    }
    for name, value in changes.items():
        monkeypatch.setattr(settings, name, value)
    claims = {"aud": changes["smoke_oidc_audience"], "repository": changes["smoke_oidc_repository"],
              "environment": changes["smoke_oidc_environment"], "sub": changes["smoke_oidc_subject"],
              "ref": changes["smoke_oidc_ref"],
              "job_workflow_ref": changes["smoke_oidc_workflow_path"] + "@" + changes["smoke_oidc_ref"]}
    require_smoke_oidc_claims(claims)
    with pytest.raises(SmokeOidcRejected):
        require_smoke_oidc_claims(_claims())


@pytest.mark.parametrize("marker", ["", " ", "sub", "exp", "permissions", "panopticon_auth", "purpose"])
def test_smoke_marker_cannot_replace_authorization_claims(marker):
    from api.core.config import Settings
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Settings(smoke_session_claim=marker)


def test_enable_flag_is_configurable_and_requires_literal_one(monkeypatch):
    from api.core.config import settings
    monkeypatch.setattr(settings, "smoke_oidc_enable_env", "EXAMPLE_SMOKE_OIDC")
    monkeypatch.setenv("HYPERMESH_SMOKE_OIDC", "1")
    monkeypatch.delenv("EXAMPLE_SMOKE_OIDC", raising=False)
    assert not smoke_oidc_enabled()
    monkeypatch.setenv("EXAMPLE_SMOKE_OIDC", "true")
    assert not smoke_oidc_enabled()
    monkeypatch.setenv("EXAMPLE_SMOKE_OIDC", "1")
    assert smoke_oidc_enabled()
