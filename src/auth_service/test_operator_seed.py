"""Explicit test-plane bootstrap of the Keycloak-seeded network operator."""
import logging
import os
import uuid

from sqlalchemy import func, or_, select, text
from controlplane_api.config import settings
from controlplane_api.exceptions import ForbiddenException
from controlplane_db.models import Role, Tenant, User
from api.infrastructure.persistence.db_session import get_db_session
from api.infrastructure.persistence.tenant_guc import set_current_tenant_id_guc
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from api.domain.operator.population import SEEDED_TEST_ADMIN_OPERATOR_CLAIMS

EMAIL = "admin@test.hyperme.sh"
ROLE = "test-network-operator"
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


async def provision_test_operator(claims: dict, tenant_id: uuid.UUID, session=None) -> None:
    # Caller supplies claims already validated by the ordinary OIDC dependency.
    failures = eligibility_failures(claims, tenant_id)
    if failures:
        if claims.get("email") == EMAIL:
            # Names of checks only: no token, subject, password or claim values.
            logger.warning("test operator bootstrap skipped checks=%s", ",".join(failures))
        return
    await provision_operator(claims, tenant_id, email=EMAIL, role_name=ROLE,
                             permissions=SEEDED_TEST_ADMIN_OPERATOR_CLAIMS, session=session)


async def provision_operator(claims, tenant_id, *, email, role_name, permissions, session=None):
    db = session or get_db_session()
    await set_current_tenant_id_guc(db, tenant_id)
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"operator:{tenant_id}"})
    tenant = await db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if tenant is None or not tenant.is_active:
        raise ForbiddenException("Configured marketplace is unavailable")
    members = list((await db.scalars(select(User).where(
        User.tenant_id == tenant_id,
        or_(func.lower(User.email) == email, User.keycloak_sub == claims["sub"])
    ))).all())
    if len(members) > 1:
        raise ForbiddenException("Operator membership requires administrator reconciliation")
    member = members[0] if members else None
    if member is not None:
        # Never revive a revoked account, rebind an identity, or elevate an
        # existing lower-privilege membership as a side effect of login.
        if member.deleted_at is not None or not member.is_active or member.keycloak_sub != claims["sub"]:
            raise ForbiddenException("Operator membership requires administrator reconciliation")
        return
    role = await db.scalar(select(Role).where(Role.tenant_id == tenant_id, Role.name == role_name))
    if role is None:
        role = Role(id=uuid.uuid4(), tenant_id=tenant_id, name=role_name,
                    description="Explicitly provisioned network operator",
                    permissions=list(permissions))
        db.add(role)
        await db.flush()
    elif set(role.permissions) != set(permissions):
        raise ForbiddenException("Operator role requires administrator reconciliation")
    db.add(User(id=uuid.uuid4(), tenant_id=tenant_id, email=email,
                keycloak_sub=claims["sub"], first_name="Network", last_name="Operator",
                gender="other", is_active=True, role_id=role.id, password=None))
    await db.flush()
