"""Explicit test-plane bootstrap of the Keycloak-seeded network operator."""
import logging
import os
import uuid

from controlplane_api.config import settings
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID

EMAIL = "admin@test.hyperme.sh"
ROLE = "test-network-operator"
HOST_EMAIL = "leaser@test.hyperme.sh"
HOST_ROLE = "user"
TEST_ISSUER = "https://auth.test.hyperme.sh/realms/controlplane"
SEEDED_HOST_MISSING = "seeded_host_missing"
SEEDED_HOST_DUPLICATE = "seeded_host_duplicate_membership"
SEEDED_HOST_CLOSED = "seeded_host_closed"
SEEDED_HOST_INACTIVE = "seeded_host_inactive"
SEEDED_HOST_SUBJECT = "seeded_host_subject_mismatch"
SEEDED_HOST_ROLE = "seeded_host_role_unresolved"
logger = logging.getLogger(__name__)


def eligibility_failures(claims: dict, tenant_id: uuid.UUID) -> list[str]:
    issuer = (settings.keycloak_issuer or "").rstrip("/")
    token_issuer = claims.get("iss")
    realm_access = claims.get("realm_access")
    roles = realm_access.get("roles") if isinstance(realm_access, dict) else None
    checks = {
        "bootstrap_enabled": os.environ.get("SPANOPTICON_TEST_OPERATOR_BOOTSTRAP") == "1",
        "test_issuer": issuer == "https://auth.test.hyperme.sh/realms/controlplane",
        "token_issuer": isinstance(token_issuer, str) and token_issuer.rstrip("/") == issuer,
        "marketplace_tenant": tenant_id == MARKETPLACE_TENANT_ID,
        "seed_email": claims.get("email") == EMAIL,
        "verified_email": claims.get("email_verified") is True,
        "subject": isinstance(claims.get("sub"), str) and bool(claims["sub"].strip()),
        "admin_role": isinstance(roles, list) and "admin" in roles,
        "ordinary_oidc": not claims.get("spanopticon_auth") and not claims.get("purpose"),
    }
    return [name for name, passed in checks.items() if not passed]


def eligible(claims: dict, tenant_id: uuid.UUID) -> bool:
    return not eligibility_failures(claims, tenant_id)


async def provision_test_operator(claims, tenant_id, session=None):
    from auth_service.identity_owner import call
    result = await call('seed-operator', claims=claims, tenant_id=str(tenant_id))
    return result




def _host_email(claims: dict) -> str | None:
    """Seeded mailbox from the email claim, or the username when email is absent."""
    email = claims.get("email")
    if isinstance(email, str) and email.strip():
        return email.strip().lower()
    username = claims.get("preferred_username")
    if isinstance(username, str):
        candidate = username.strip().lower()
        if candidate in {HOST_EMAIL, "leaser"}:
            return HOST_EMAIL
    return None


def _seeded_host_claim(claims: dict, tenant_id: uuid.UUID) -> str | None:
    """Test-issuer leaser only. Returns the subject, or nothing when ineligible."""
    issuer = (settings.keycloak_issuer or "").rstrip("/")
    token_issuer = claims.get("iss")
    subject = claims.get("sub")
    if (
        issuer != TEST_ISSUER
        or not isinstance(token_issuer, str)
        or token_issuer.rstrip("/") != TEST_ISSUER
        or tenant_id != MARKETPLACE_TENANT_ID
        or _host_email(claims) != HOST_EMAIL
        or not isinstance(subject, str)
        or not subject.strip()
        or len(subject) > 512
        or claims.get("spanopticon_auth")
        or claims.get("purpose")
    ):
        return None
    return subject.strip()


def _sqlstate(exc: BaseException) -> str | None:
    orig = getattr(exc, "orig", None)
    state = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    return str(state) if state else None






async def ensure_seeded_host_role(claims, tenant_id, session=None):
    from auth_service.identity_owner import call
    result = await call('seed-host', claims=claims, tenant_id=str(tenant_id))
    return result
