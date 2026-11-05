"""Explicit test-plane bootstrap of the Keycloak-seeded network operator."""
import logging
import os
import uuid

from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, IntegrityError
from controlplane_api.config import settings
from controlplane_api.exceptions import ForbiddenException
from controlplane_db.models import Role, Tenant, User
from api.infrastructure.persistence.db_session import get_db_session
from api.infrastructure.persistence.tenant_guc import set_current_tenant_id_guc
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from api.domain.operator.population import SEEDED_TEST_ADMIN_OPERATOR_CLAIMS

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


async def _resolved_tenant_role(db, member: User) -> Role | None:
    """Role visible to tenant switch. A platform role of the same name is not it."""
    if member.role_id is None or member.tenant_id is None:
        return None
    return await db.scalar(select(Role).where(
        Role.id == member.role_id, Role.tenant_id == member.tenant_id,
    ))


async def _tenant_user_role(db, tenant_id: uuid.UUID) -> Role | None:
    """Tenant-scoped member role. Create it only when this seeded host needs it."""
    found = await db.scalars(select(Role).where(
        Role.tenant_id == tenant_id, func.lower(Role.name) == HOST_ROLE,
    ).order_by(Role.created_at.asc(), Role.id.asc()).limit(1))
    role = found.first()
    if role is not None:
        return role
    try:
        async with db.begin_nested():
            await db.execute(pg_insert(Role).values(
                id=uuid.uuid4(), tenant_id=tenant_id, name=HOST_ROLE,
                description=None, permissions=[],
            ).on_conflict_do_nothing())
    except IntegrityError:
        pass
    found = await db.scalars(select(Role).where(
        Role.tenant_id == tenant_id, func.lower(Role.name) == HOST_ROLE,
    ).order_by(Role.created_at.asc(), Role.id.asc()).limit(1))
    return found.first()


async def ensure_seeded_host_role(claims: dict, tenant_id: uuid.UUID, session=None) -> str | None:
    """Make the pan-test leaser switchable. Do not invent admin.

    Tenant switch refuses a membership whose role does not resolve in that
    tenant. The seeded host used to pass by substituting the name admin, including
    when ``role_id`` pointed at a platform role or was null. On the test issuer
    only, one active marketplace row for that mailbox gets the tenant ``user``
    role in either case. A null subject is bound to this verified caller. A
    different subject, an inactive or closed row, and every other identity are
    left unchanged.

    Returns a stable denial code when this caller is that host and the row
    still cannot switch. Returns None when the caller is someone else, or when
    the row is already switchable or was repaired.
    """
    subject = _seeded_host_claim(claims, tenant_id)
    if subject is None:
        return None
    db = session or get_db_session()
    await set_current_tenant_id_guc(db, tenant_id)
    members = list((await db.scalars(select(User).where(
        User.tenant_id == tenant_id,
        func.lower(User.email) == HOST_EMAIL,
    ))).all())
    if not members:
        logger.warning("seeded host switch denied code=%s", SEEDED_HOST_MISSING)
        return SEEDED_HOST_MISSING
    if len(members) != 1:
        logger.warning("seeded host switch denied code=%s", SEEDED_HOST_DUPLICATE)
        return SEEDED_HOST_DUPLICATE
    member = members[0]
    if member.deleted_at is not None:
        logger.warning("seeded host switch denied code=%s", SEEDED_HOST_CLOSED)
        return SEEDED_HOST_CLOSED
    if not member.is_active:
        logger.warning("seeded host switch denied code=%s", SEEDED_HOST_INACTIVE)
        return SEEDED_HOST_INACTIVE
    if member.keycloak_sub is not None and member.keycloak_sub != subject:
        logger.warning("seeded host switch denied code=%s", SEEDED_HOST_SUBJECT)
        return SEEDED_HOST_SUBJECT
    if await _resolved_tenant_role(db, member) is None:
        role = await _tenant_user_role(db, tenant_id)
        if role is None:
            logger.warning("seeded host switch denied code=%s", SEEDED_HOST_ROLE)
            return SEEDED_HOST_ROLE
        previous_role = member.role_id
        try:
            async with db.begin_nested():
                member.role_id = role.id
                await db.flush()
        except DBAPIError as exc:
            member.role_id = previous_role
            if _sqlstate(exc) == "42501":
                logger.warning("seeded host switch denied code=%s", SEEDED_HOST_CLOSED)
                return SEEDED_HOST_CLOSED
            raise
    if member.keycloak_sub is None:
        taken = await db.scalar(select(User.id).where(
            User.tenant_id == tenant_id,
            User.keycloak_sub == subject,
            User.id != member.id,
        ))
        if taken is None:
            try:
                async with db.begin_nested():
                    member.keycloak_sub = subject
                    await db.flush()
            except DBAPIError:
                # Role repair still lets an email match switch. Leave the row unbound
                # when this subject is retired or already stored on another profile.
                member.keycloak_sub = None
    return None
