"""Test-plane smoke session. GitHub OIDC in, tenant-session JWT out.

Keycloak admin REST is not on the public auth host (HAProxy answers
``/admin`` with 404). A workflow cannot create a confidential client
from Actions. This door is the M2M mint path instead: the smoke job
presents a GitHub OIDC token for Environment ``test``, and auth-service
enrolls one marketplace renter and returns a short-lived tenant-session
JWT. The job then mints and revokes renter keys on the existing
``/api/v1/api-keys`` routes. Nothing here is stored. Prod stays off
unless ``KEYCLOAK_ISSUER`` contains ``.test.`` or ``HYPERMESH_SMOKE_OIDC=1``.
``HYPERMESH_SMOKE_OIDC=0`` forces it off.
"""

from __future__ import annotations

import os
from typing import Any

import jwt
from jwt import InvalidTokenError, PyJWKClient

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_JWKS_URL = "https://token.actions.githubusercontent.com/.well-known/jwks"
SMOKE_OIDC_AUDIENCE = "hypermesh-gateway-smoke"
SMOKE_OIDC_REPOSITORY = "FyberLabs/panopticon"
SMOKE_OIDC_ENVIRONMENT = "test"
SMOKE_OIDC_SUBJECT = "repo:FyberLabs/panopticon:environment:test"
SMOKE_EMAIL = "hypermesh-smoke@test.hyperme.sh"
SMOKE_KEYCLOAK_SUB = "c0ffee00-5a0e-4000-8000-0000000005a0"


class SmokeOidcRejected(Exception):
    """The bearer is not the test-plane smoke job. Detail stays generic."""


def smoke_oidc_enabled() -> bool:
    """On for the test issuer. Off for prod, laptop, and an explicit 0."""

    flag = os.environ.get("HYPERMESH_SMOKE_OIDC", "").strip().lower()
    if flag in {"0", "false", "no", "off"}:
        return False
    if flag in {"1", "true", "yes", "on"}:
        return True
    issuer = os.environ.get("KEYCLOAK_ISSUER", "")
    if not issuer:
        from api.core.config import settings

        issuer = settings.keycloak_issuer or ""
    return ".test." in issuer


def require_smoke_oidc_claims(claims: dict[str, Any]) -> None:
    """Pin repository, environment, and subject. A pull-request token is not this job."""

    repository = str(claims.get("repository") or "")
    environment = str(claims.get("environment") or "")
    subject = str(claims.get("sub") or "")
    if repository != SMOKE_OIDC_REPOSITORY:
        raise SmokeOidcRejected()
    if environment != SMOKE_OIDC_ENVIRONMENT:
        raise SmokeOidcRejected()
    if subject != SMOKE_OIDC_SUBJECT:
        raise SmokeOidcRejected()


def verify_github_actions_oidc(
    token: str,
    *,
    jwks_client: PyJWKClient | None = None,
) -> dict[str, Any]:
    """Validate a GitHub Actions OIDC token for the smoke audience."""

    client = jwks_client or PyJWKClient(GITHUB_JWKS_URL)
    try:
        signing_key = client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=SMOKE_OIDC_AUDIENCE,
            issuer=GITHUB_OIDC_ISSUER,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except InvalidTokenError as exc:
        raise SmokeOidcRejected() from exc
    if not isinstance(payload, dict):
        raise SmokeOidcRejected()
    require_smoke_oidc_claims(payload)
    return payload
