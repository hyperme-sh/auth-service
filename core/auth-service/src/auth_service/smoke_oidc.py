"""Test-plane smoke session. GitHub OIDC in, tenant-session JWT out.

A deployment declares the smoke identity and GitHub workflow in settings.
The job enrolls a marketplace renter and receives a short-lived session, then
mints and revokes renter keys through the existing API. No credential is stored.
The configured enable flag must be literal 1; startup rejects enabled smoke
sessions unless the issuer and every declared auth host belong to the test plane.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import jwt
from jwt import InvalidTokenError, PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from api.core.config import settings

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_JWKS_URL = "https://token.actions.githubusercontent.com/.well-known/jwks"

SMOKE_OIDC_AUDIENCE = settings.smoke_oidc_audience
SMOKE_OIDC_REPOSITORY = settings.smoke_oidc_repository
SMOKE_OIDC_ENVIRONMENT = settings.smoke_oidc_environment
SMOKE_OIDC_SUBJECT = settings.smoke_oidc_subject
SMOKE_WORKFLOW_PATH = settings.smoke_oidc_workflow_path
SMOKE_OIDC_REF = settings.smoke_oidc_ref
SMOKE_JOB_WORKFLOW_REF = f"{SMOKE_WORKFLOW_PATH}@{SMOKE_OIDC_REF}"
SMOKE_EMAIL = settings.smoke_session_email
SMOKE_KEYCLOAK_SUB = settings.smoke_session_subject
_TEST_MARKER = ".test."


class SmokeOidcRejected(Exception):
    """The bearer is not the test-plane smoke job. Detail stays generic."""


class SmokeOidcUnavailable(Exception):
    """GitHub's JWKS could not be fetched. The token was not accepted."""


class SmokeOidcMisconfigured(RuntimeError):
    """The smoke door is explicitly on, and this plane is not test."""


def smoke_oidc_enabled() -> bool:
    """On only when the process was started with the configured smoke OIDC enable flag=1."""

    return os.environ.get(settings.smoke_oidc_enable_env, "").strip() == "1"


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
    declared = [settings.smoke_oidc_audience, settings.smoke_oidc_repository,
                settings.smoke_oidc_environment, settings.smoke_oidc_subject,
                settings.smoke_oidc_workflow_path, settings.smoke_oidc_ref,
                settings.smoke_session_email, settings.smoke_session_subject,
                settings.smoke_session_username, settings.smoke_session_claim]
    if not all(value.strip() for value in declared):
        raise SmokeOidcMisconfigured("Smoke OIDC requires a complete identity and workflow declaration")
    issuer = _issuer()
    hosts = _plane_hosts(issuer)
    issuer_ok = _TEST_MARKER in issuer
    hosts_ok = bool(hosts) and all(_TEST_MARKER in host for host in hosts)
    if issuer_ok and hosts_ok:
        return
    raise SmokeOidcMisconfigured(
        "Smoke OIDC requires a test issuer and host"
    )


def _audience_ok(audience: object) -> bool:
    if isinstance(audience, str):
        return audience == settings.smoke_oidc_audience
    if isinstance(audience, list) and all(isinstance(item, str) for item in audience):
        return audience == [settings.smoke_oidc_audience]
    return False


def _job_workflow_ref_ok(value: object) -> bool:
    """Accept only the smoke workflow on ``refs/heads/main``.

    A feature-branch ref and a ``refs/pull/...`` ref are both rejected.
    """

    return value == f"{settings.smoke_oidc_workflow_path}@{settings.smoke_oidc_ref}"


def require_smoke_oidc_claims(claims: dict[str, Any]) -> None:
    """Pin repository, environment, job_workflow_ref, ref, and audience.

    ``job_workflow_ref`` is the workflow file that requested the token.
    It is accepted only as
    the configured workflow and ref.
    The ``ref`` claim must be ``refs/heads/main``. ``workflow_ref`` is not
    accepted in its place. A pull-request subject is not this job.
    """

    repository = str(claims.get("repository") or "")
    environment = str(claims.get("environment") or "")
    subject = str(claims.get("sub") or "")
    if repository != settings.smoke_oidc_repository:
        raise SmokeOidcRejected()
    if environment != settings.smoke_oidc_environment:
        raise SmokeOidcRejected()
    if subject != settings.smoke_oidc_subject:
        raise SmokeOidcRejected()
    if not _job_workflow_ref_ok(claims.get("job_workflow_ref")):
        raise SmokeOidcRejected()
    if claims.get("ref") != settings.smoke_oidc_ref:
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
            audience=settings.smoke_oidc_audience,
            issuer=GITHUB_OIDC_ISSUER,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except PyJWKClientConnectionError as exc:
        raise SmokeOidcUnavailable() from exc
    except (InvalidTokenError, PyJWKClientError) as exc:
        raise SmokeOidcRejected() from exc
    if not isinstance(payload, dict):
        raise SmokeOidcRejected()
    require_smoke_oidc_claims(payload)
    return payload
