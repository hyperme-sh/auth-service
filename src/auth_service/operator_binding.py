"""Environment-bound operator access from validated, session-bound OIDC claims."""
import os
import uuid

from controlplane_api.config import settings
from api.domain.operator.population import SEEDED_TEST_ADMIN_OPERATOR_CLAIMS
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from auth_service.test_operator_seed import provision_operator, eligible as test_eligible

PRODUCTION_ISSUER = "https://auth.hyperme.sh/realms/controlplane"
ROLE = "entra-network-operator"


def _uuid(value):
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def eligible(claims, tenant_id):
    tenant = _uuid(os.getenv("SPANOPTICON_OPERATOR_ENTRA_TENANT_ID"))
    user = _uuid(os.getenv("SPANOPTICON_OPERATOR_ENTRA_OBJECT_ID"))
    return bool(
        tenant and user
        and settings.keycloak_issuer.rstrip("/") == PRODUCTION_ISSUER
        and claims.get("iss") == PRODUCTION_ISSUER
        and tenant_id == MARKETPLACE_TENANT_ID
        and claims.get("login_provider") == "microsoft"
        and _uuid(claims.get("entra_tenant_id")) == tenant
        and _uuid(claims.get("entra_object_id")) == user
        and isinstance(claims.get("sub"), str) and claims["sub"].strip()
        and isinstance(claims.get("email"), str) and claims["email"].strip()
        and not claims.get("spanopticon_auth") and not claims.get("purpose")
    )


async def provision(claims, tenant_id, session=None):
    if eligible(claims, tenant_id):
        # No durable operator permissions: each session must prove the binding.
        await provision_operator(claims, tenant_id, email=claims["email"].strip().lower(),
                                 role_name=ROLE, permissions=(), session=session)


def permissions(claims, tenant_id, role_name, proposed):
    if settings.keycloak_issuer.rstrip("/") != PRODUCTION_ISSUER:
        if role_name == "test-network-operator" and not test_eligible(claims, tenant_id):
            return [p for p in proposed if not p.startswith("operator:")]
        return proposed
    result = [p for p in proposed if not p.startswith("operator:")]
    if eligible(claims, tenant_id):
        result.extend(SEEDED_TEST_ADMIN_OPERATOR_CLAIMS)
    return result
