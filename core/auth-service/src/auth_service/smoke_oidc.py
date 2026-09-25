"""Test-plane smoke session. GitHub OIDC in, tenant-session JWT out.

Keycloak admin REST is not on the public auth host (HAProxy answers
``/admin`` with 404). A workflow cannot create a confidential client
from Actions. This door is the M2M mint path instead: the smoke job
presents a GitHub OIDC token for Environment ``test``, and auth-service
enrolls one marketplace renter and returns a short-lived tenant-session
JWT. The job then mints and revokes renter keys on the existing
``/api/v1/api-keys`` routes. Nothing here is stored.

The route stays off unless ``HYPERMESH_SMOKE_OIDC`` is exactly ``1``.
That value is set on auth-service in ``docker-compose.vm.yaml`` only.
Startup refuses to boot when the flag is ``1`` and ``KEYCLOAK_ISSUER``
or its host (or ``KEYCLOAK_HOSTNAME`` / ``KEYCLOAK_HOSTNAME_PUBLIC``)
has no ``.test.``.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import jwt
from jwt import InvalidTokenError, PyJWKClient

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_JWKS_URL = "https://token.actions.githubusercontent.com/.well-known/jwks"
SMOKE_OIDC_AUDIENCE = "hypermesh-gateway-smoke"
SMOKE_OIDC_REPOSITORY = "FyberLabs/panopticon"
SMOKE_OIDC_ENVIRONMENT = "test"
SMOKE_OIDC_SUBJECT = "repo:FyberLabs/panopticon:environment:test"
SMOKE_WORKFLOW_PATH = (
    "FyberLabs/panopticon/.github/workflows/hypermesh-gateway-smoke.yml"
)
SMOKE_EMAIL = "hypermesh-smoke@test.hyperme.sh"
SMOKE_KEYCLOAK_SUB = "c0ffee00-5a0e-4000-8000-0000000005a0"
_TEST_MARKER = ".test."


class SmokeOidcRejected(Exception):
    """The bearer is not the test-plane smoke job. Detail stays generic."""


class SmokeOidcMisconfigured(RuntimeError):
    """The smoke door is explicitly on, and this plane is not test."""


def smoke_oidc_enabled() -> bool:
    """On only when the process was started with HYPERMESH_SMOKE_OIDC=1."""

    return os.environ.get("HYPERMESH_SMOKE_OIDC", "").strip() == "1"


def _issuer() -> str:
    issuer = os.environ.get("KEYCLOAK_ISSUER", "").strip()
    if issuer:
        return issuer
    from api.core.config import settings

    return (settings.keycloak_issuer or "").strip()


def _host_token(raw: str) -> str:
    text = raw.strip()
    if not text:
        return ""
    if "://" in text:
        return (urlparse(text).hostname or "").strip()
    return text.split("/")[0].split(":")[0].strip()


def _plane_hosts(issuer: str) -> list[str]:
    hosts = [_host_token(issuer)]
    for name in ("KEYCLOAK_HOSTNAME", "KEYCLOAK_HOSTNAME_PUBLIC"):
        hosts.append(_host_token(os.environ.get(name, "")))
    return [host for host in hosts if host]


def assert_smoke_oidc_plane() -> None:
    """Fail closed at startup when the flag is on outside the test plane.

    A prod issuer or host has no ``.test.``. An empty issuer fails the
    same way. The route does not turn on from the issuer alone.
    """

    if not smoke_oidc_enabled():
        return
    issuer = _issuer()
    hosts = _plane_hosts(issuer)
    issuer_ok = _TEST_MARKER in issuer
    hosts_ok = bool(hosts) and all(_TEST_MARKER in host for host in hosts)
    if issuer_ok and hosts_ok:
        return
    raise SmokeOidcMisconfigured(
        "HYPERMESH_SMOKE_OIDC=1 requires a test issuer and host"
    )


def _audience_ok(audience: object) -> bool:
    if isinstance(audience, str):
        return audience == SMOKE_OIDC_AUDIENCE
    if isinstance(audience, list) and all(isinstance(item, str) for item in audience):
        return audience == [SMOKE_OIDC_AUDIENCE]
    return False


def _job_workflow_ref_ok(value: object) -> bool:
    """GitHub job_workflow_ref is ``<repo>/.github/workflows/<file>@refs/...``."""

    if not isinstance(value, str):
        return False
    path, separator, ref = value.partition("@")
    return (
        bool(separator)
        and path == SMOKE_WORKFLOW_PATH
        and ref.startswith("refs/")
        and len(ref) > len("refs/")
    )


def require_smoke_oidc_claims(claims: dict[str, Any]) -> None:
    """Pin repository, environment, job_workflow_ref, and audience.

    ``job_workflow_ref`` is the workflow file that requested the token.
    ``workflow_ref`` is not accepted in its place. A pull-request subject
    is not this job.
    """

    repository = str(claims.get("repository") or "")
    environment = str(claims.get("environment") or "")
    subject = str(claims.get("sub") or "")
    if repository != SMOKE_OIDC_REPOSITORY:
        raise SmokeOidcRejected()
    if environment != SMOKE_OIDC_ENVIRONMENT:
        raise SmokeOidcRejected()
    if subject != SMOKE_OIDC_SUBJECT:
        raise SmokeOidcRejected()
    if not _job_workflow_ref_ok(claims.get("job_workflow_ref")):
        raise SmokeOidcRejected()
    if not _audience_ok(claims.get("aud")):
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
