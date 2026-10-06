"""Explicit test-plane bootstrap of the Keycloak-seeded network operator."""
import os
import uuid

from sqlalchemy import func, select, text
from controlplane_api.config import settings
from controlplane_api.exceptions import ForbiddenException
from controlplane_db.models import Role, Tenant, User
from api.infrastructure.persistence.db_session import get_db_session
from api.infrastructure.persistence.tenant_guc import set_current_tenant_id_guc
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from api.domain.operator.population import SEEDED_TEST_ADMIN_OPERATOR_CLAIMS

EMAIL = "admin@test.hyperme.sh"
ROLE = "test-network-operator"


def eligible(claims: dict, tenant_id: uuid.UUID) -> bool:
    issuer = (settings.keycloak_issuer or "").rstrip("/")
    return bool(
        os.environ.get("PANOPTICON_TEST_OPERATOR_BOOTSTRAP") == "1"
        and issuer == "https://auth.test.hyperme.sh/realms/controlplane"
        and claims.get("iss", "").rstrip("/") == issuer
        and tenant_id == MARKETPLACE_TENANT_ID
        and claims.get("email") == EMAIL
        and claims.get("email_verified") is True
        and claims.get("preferred_username") == "admin"
        and isinstance(claims.get("sub"), str) and claims["sub"].strip()
        and "admin" in (claims.get("realm_access") or {}).get("roles", [])
        and not claims.get("panopticon_auth") and not claims.get("purpose")
    )


async def provision_test_operator(claims: dict, tenant_id: uuid.UUID, session=None) -> None:
    # Caller supplies claims already validated by the ordinary OIDC dependency.
    if not eligible(claims, tenant_id):
        return
    db = session or get_db_session()
    await set_current_tenant_id_guc(db, tenant_id)
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"test-operator:{tenant_id}"})
    tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if tenant is None or not tenant.is_active:
        raise ForbiddenException("Configured test marketplace is unavailable")
    member = await db.scalar(select(User).where(User.tenant_id == tenant_id, func.lower(User.email) == EMAIL))
    if member is not None:
        # Never revive a revoked account, rebind an identity, or elevate an
        # existing lower-privilege membership as a side effect of login.
        if member.deleted_at is not None or not member.is_active or member.keycloak_sub != claims["sub"]:
            raise ForbiddenException("Test operator membership requires administrator reconciliation")
        return
    role = await db.scalar(select(Role).where(Role.tenant_id == tenant_id, Role.name == ROLE))
    if role is None:
        role = Role(id=uuid.uuid4(), tenant_id=tenant_id, name=ROLE,
                    description="Explicitly provisioned test network operator",
                    permissions=list(SEEDED_TEST_ADMIN_OPERATOR_CLAIMS))
        db.add(role)
        await db.flush()
    elif set(role.permissions) != set(SEEDED_TEST_ADMIN_OPERATOR_CLAIMS):
        raise ForbiddenException("Test operator role requires administrator reconciliation")
    db.add(User(id=uuid.uuid4(), tenant_id=tenant_id, email=EMAIL,
                keycloak_sub=claims["sub"], first_name="Test", last_name="Operator",
                gender="other", is_active=True, role_id=role.id, password=None))
    await db.flush()
