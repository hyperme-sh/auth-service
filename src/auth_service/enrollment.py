"""Enrollment role-grant job after Keycloak identify + SIWE bind.

May add renter or host for the identified person, then INSERT the
marketplace users row and those groups. Org admin is not added unless
a target-tenant-bound token already has it, and is not granted together with
renter/host — that invite stays POST /api/v1/users.
Reuses the existing renter group, identity-bound host organization + host group, and
portal admin role. Membership is an internal users-row write
(service/repository, not the renter JWT and not POST /api/v1/users).
Does not enroll a device, mint an enroll token, invent a renter role,
or add a payment role.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass

import bcrypt
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.common.portal_controls import (
    GROUP_HOST,
    GROUP_RENTER,
    collect_groups,
    evaluate_portal_controls,
    is_org_admin,
)
from api.infrastructure.persistence.tenant_guc import set_current_tenant_id_guc
from api.infrastructure.persistence.tenant_membership import (
    MARKETPLACE_TENANT_ID,
    create_tenant_membership_row,
    get_tenant_membership_row,
)
from controlplane_db.models import (
    ApiKey,
    Group,
    Role,
    Tenant,
    User,
    UserGroupMembership,
    UserWalletBinding,
)

from auth_service.schemas import AuthMeResponse
from auth_service.host_binding_client import host_binding_client

HELD_RENTER = "renter"
HELD_HOST = "host"
HELD_ORG_ADMIN = "org_admin"
GRANTABLE = frozenset({HELD_RENTER, HELD_HOST, HELD_ORG_ADMIN})

NETWORK_ADMIN_SEED_EMAIL = "admin@test.hyperme.sh"
NETWORK_ADMIN_SEED_USERNAME = "admin"
# #90 fixtures stay split. Enrollment must not merge them.
PAN_TEST_SEED_EMAILS = frozenset(
    {
        "renter@test.hyperme.sh",
        "leaser@test.hyperme.sh",
        NETWORK_ADMIN_SEED_EMAIL,
    }
)
FORBIDDEN_GRANT_ALIASES = frozenset(
    {
        "payment",
        "payments",
        "billing",
        "billing_manager",
        "leaser",
    }
)

# Existing tenant role used as the group FK. Not a new renter role.
_GROUP_ROLE_NAME = "user"
_ORG_ADMIN_ROLE_NAME = "admin"


@dataclass(frozen=True, slots=True)
class RenterGrant:
    tenant_membership: bool
    group: str
    api_key_prefix: str | None
    can_checkout: bool
    can_see_leases: bool
    can_mint_keys: bool


@dataclass(frozen=True, slots=True)
class HostGrant:
    organization_id: uuid.UUID
    group: str
    device_enrolled: bool


@dataclass(frozen=True, slots=True)
class OrgAdminGrant:
    portal_role: str
    email: str
    network_admin_seed: bool
    keycloak_bootstrap_admin: bool


@dataclass(frozen=True, slots=True)
class EnrollmentGrantResult:
    granted: tuple[str, ...]
    refused: tuple[str, ...]
    wallet_address: str | None
    renter: RenterGrant | None = None
    host: HostGrant | None = None
    org_admin: OrgAdminGrant | None = None
    device_enrolled: bool = False

    def as_public_dict(self) -> dict:
        """Public grant summary. Never includes secrets, signatures, or tokens."""
        body: dict = {
            "granted": list(self.granted),
            "refused": list(self.refused),
            "wallet_address": self.wallet_address,
            "device_enrolled": False,
            "renter": None,
            "host": None,
            "org_admin": None,
        }
        if self.renter is not None:
            body["renter"] = {
                "tenant_membership": self.renter.tenant_membership,
                "group": self.renter.group,
                "api_key_prefix": self.renter.api_key_prefix,
                "can_checkout": self.renter.can_checkout,
                "can_see_leases": self.renter.can_see_leases,
                "can_mint_keys": self.renter.can_mint_keys,
            }
        if self.host is not None:
            body["host"] = {
                "organization_id": str(self.host.organization_id),
                "group": self.host.group,
                "device_enrolled": False,
            }
        if self.org_admin is not None:
            body["org_admin"] = {
                "portal_role": self.org_admin.portal_role,
                "email": self.org_admin.email,
                "network_admin_seed": self.org_admin.network_admin_seed,
                "keycloak_bootstrap_admin": False,
            }
        return body


class EnrollmentError(ValueError):
    """Enrollment grant cannot proceed."""


def _token_held_roles(user: AuthMeResponse) -> set[str]:
    token_held: set[str] = set()
    groups = collect_groups(user.roles, user.groups)
    if GROUP_RENTER in groups:
        token_held.add(HELD_RENTER)
    if GROUP_HOST in groups:
        token_held.add(HELD_HOST)
    if is_org_admin(user.roles):
        token_held.add(HELD_ORG_ADMIN)
    for role in user.roles or ():
        n = str(role).strip().lower()
        if n == HELD_ORG_ADMIN:
            token_held.add(HELD_ORG_ADMIN)
    return token_held


def held_roles_from_identity(
    user: AuthMeResponse,
    requested: list[str] | None = None,
    *,
    tenant_id: uuid.UUID = MARKETPLACE_TENANT_ID,
) -> tuple[frozenset[str], tuple[str, ...]]:
    """Choose renter/host for the identified person; org admin stays invite-only.

    A new Keycloak user is not in the renter group. Enrollment may add
    renter or host, then INSERT the marketplace users row and those
    groups. Org admin requires a target-tenant-bound token that already has it, and
    is never granted in the same job as renter/host. Invite stays
    POST /api/v1/users (can_invite_members).
    """
    token_held = _token_held_roles(user)
    asked: list[str] = []
    for raw in requested or ():
        name = str(raw).strip().lower()
        if name:
            asked.append(name)

    if not asked:
        granted = {name for name in token_held if name != HELD_ORG_ADMIN}
        if HELD_RENTER not in granted and HELD_HOST not in granted:
            granted.add(HELD_RENTER)
        return frozenset(granted), ()

    refused: list[str] = []
    granted: set[str] = set()
    asked_renter_or_host = any(name in {HELD_RENTER, HELD_HOST} for name in asked)
    for name in asked:
        if name in FORBIDDEN_GRANT_ALIASES or name not in GRANTABLE:
            refused.append(name)
            continue
        if name == HELD_ORG_ADMIN:
            if (
                asked_renter_or_host
                or HELD_ORG_ADMIN not in token_held
                or user.tenant_id != tenant_id
            ):
                refused.append(name)
            else:
                granted.add(HELD_ORG_ADMIN)
            continue
        granted.add(name)
    return frozenset(granted), tuple(refused)


def _email_norm(user: AuthMeResponse) -> str:
    if not user.email or not str(user.email).strip():
        raise EnrollmentError("identified person has no email")
    return str(user.email).strip().lower()


def _name_parts(user: AuthMeResponse) -> tuple[str, str]:
    preferred = (user.preferred_username or "").strip()
    if preferred and "@" not in preferred:
        return preferred[:255], "Member"
    email = _email_norm(user)
    local = email.split("@", 1)[0][:255]
    return local or "Member", "Member"


async def _require_tenant(session: AsyncSession, tenant_id: uuid.UUID) -> Tenant:
    row = await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = row.scalar_one_or_none()
    if tenant is None:
        raise EnrollmentError("tenant does not exist")
    return tenant


async def _bound_wallet(
    session: AsyncSession, keycloak_sub: str
) -> str | None:
    found = await session.execute(
        select(UserWalletBinding.wallet_address).where(
            UserWalletBinding.keycloak_sub == keycloak_sub
        )
    )
    return found.scalar_one_or_none()


async def _select_role(
    session: AsyncSession, tenant_id: uuid.UUID, name: str
) -> Role | None:
    found = await session.execute(
        select(Role)
        .where(
            Role.tenant_id == tenant_id,
            func.lower(Role.name) == name.lower(),
        )
        .order_by(Role.created_at.asc(), Role.id.asc())
        .limit(1)
    )
    return found.scalars().first()


async def _select_group(
    session: AsyncSession, tenant_id: uuid.UUID, name: str
) -> Group | None:
    found = await session.execute(
        select(Group)
        .where(
            Group.tenant_id == tenant_id,
            func.lower(Group.name) == name.lower(),
        )
        .order_by(Group.created_at.asc(), Group.id.asc())
        .limit(1)
    )
    return found.scalars().first()


async def _get_or_create_role(
    session: AsyncSession, tenant_id: uuid.UUID, name: str
) -> Role:
    """Tenant-scoped role. A NULL-tenant row with the same name is not reused."""
    role = await _select_role(session, tenant_id, name)
    if role is not None:
        return role
    try:
        async with session.begin_nested():
            await session.execute(
                pg_insert(Role)
                .values(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    name=name,
                    description=None,
                    permissions=[],
                )
                .on_conflict_do_nothing()
            )
    except IntegrityError:
        pass
    role = await _select_role(session, tenant_id, name)
    if role is None:
        raise EnrollmentError(f"role {name} was not created")
    return role


async def _get_or_create_group(
    session: AsyncSession, tenant_id: uuid.UUID, name: str, role_id: uuid.UUID
) -> Group:
    group = await _select_group(session, tenant_id, name)
    if group is not None:
        return group
    try:
        async with session.begin_nested():
            await session.execute(
                pg_insert(Group)
                .values(
                    id=uuid.uuid4(),
                    tenant_id=tenant_id,
                    name=name,
                    description=None,
                    role_id=role_id,
                )
                .on_conflict_do_nothing()
            )
    except IntegrityError:
        pass
    group = await _select_group(session, tenant_id, name)
    if group is None:
        raise EnrollmentError(f"group {name} was not created")
    return group


async def _lock_host_identity(
    session: AsyncSession, tenant_id: uuid.UUID, subject: str
) -> None:
    """Serialize auth grant mutations after owner organization resolution.

    Transaction-scoped PostgreSQL locks work across replicas and disappear on
    rollback/disconnect. Hash collisions only serialize unrelated grants.
    """
    digest = hashlib.sha256(
        b"host-org-binding-v1\0" + tenant_id.bytes + subject.encode("utf-8")
    ).digest()
    await session.execute(text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": int.from_bytes(digest[:8], "big", signed=True)})


async def _ensure_membership_user(
    session: AsyncSession, tenant_id: uuid.UUID, user: AuthMeResponse, *, role_id: uuid.UUID
) -> User:
    """Service write for the existing marketplace tenant.

    Not POST /api/v1/users (invite JWT + can_invite_members). Not a
    public self-join. Not POST /api/v1/tenants/. The identified person
    is the Keycloak subject; this call is the workflow acting as the
    service with an explicit tenant id.
    """
    email = _email_norm(user)
    row = await get_tenant_membership_row(
        session, tenant_id, email=email, keycloak_sub=user.sub
    )
    if row is not None:
        if row.keycloak_sub and row.keycloak_sub != user.sub:
            raise EnrollmentError("Membership email is bound to another identity")
        return row
    first, last = _name_parts(user)
    row = await create_tenant_membership_row(
        session,
        tenant_id,
        email=email,
        first_name=first,
        last_name=last,
        gender="unspecified",
        is_active=True,
        keycloak_sub=user.sub,
    )
    # New self-enrolled members need an explicit low-privilege target role.
    # Tenant switching never invents a role for existing incomplete records.
    row.role_id = role_id
    await session.flush()
    return row


async def _ensure_group_member(
    session: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID, group_id: uuid.UUID
) -> None:
    found = await session.execute(
        select(UserGroupMembership.id).where(
            UserGroupMembership.tenant_id == tenant_id,
            UserGroupMembership.user_id == user_id,
            UserGroupMembership.group_id == group_id,
        )
    )
    if found.scalar_one_or_none() is not None:
        return
    session.add(
        UserGroupMembership(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            user_id=user_id,
            group_id=group_id,
        )
    )
    await session.flush()


async def _ensure_renter_api_key(
    session: AsyncSession, tenant_id: uuid.UUID, user: AuthMeResponse
) -> str:
    marker = str(user.sub or _email_norm(user))
    found = await session.execute(
        select(ApiKey).where(
            ApiKey.tenant_id == tenant_id,
            ApiKey.created_by_sub == marker,
            ApiKey.revoked_at.is_(None),
            ApiKey.purpose == "renter",
        )
    )
    existing = found.scalars().first()
    if existing is not None:
        return existing.key_prefix
    prefix = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    secret_hash = bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt()).decode("ascii")
    # Drop plaintext immediately. Never return it.
    del secret
    session.add(
        ApiKey(
            tenant_id=tenant_id,
            key_prefix=prefix,
            secret_hash=secret_hash,
            name="enrollment-renter",
            scopes=[],
            created_by_sub=marker,
            purpose="renter",
        )
    )
    await session.flush()
    return prefix


async def grant_held_roles(
    session: AsyncSession,
    user: AuthMeResponse,
    *,
    tenant_id: uuid.UUID | None = None,
    requested: list[str] | None = None,
) -> EnrollmentGrantResult:
    """Job: add renter/host as requested, then INSERT marketplace membership.

    Org admin is not added unless the Keycloak token already has it, and
    is not granted together with renter/host. Default tenant is the
    marketplace tenant ``8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d``.
    """
    if not user.sub or not user.sub.strip() or len(user.sub) > 512:
        raise EnrollmentError("A nonempty Keycloak subject of at most 512 characters is required")
    tenant_id = tenant_id or MARKETPLACE_TENANT_ID
    await _require_tenant(session, tenant_id)
    await set_current_tenant_id_guc(session, tenant_id)

    held, refused = held_roles_from_identity(user, requested, tenant_id=tenant_id)
    host_org_id = None
    if HELD_HOST in held:
        _email_norm(user)  # Reject invalid identity before reserving owner metadata.
        # Resolve before taking the local grant lock: owner uses the same key in
        # its own transaction. Never wait on owner HTTP while holding that lock.
        host_org_id = await host_binding_client().resolve(tenant_id, user.sub)
        await _lock_host_identity(session, tenant_id, user.sub)
    wallet = await _bound_wallet(session, user.sub)

    group_role = await _get_or_create_role(session, tenant_id, _GROUP_ROLE_NAME)
    member: User | None = None
    if held:
        member = await _ensure_membership_user(session, tenant_id, user, role_id=group_role.id)

    renter_grant: RenterGrant | None = None
    host_grant: HostGrant | None = None
    org_admin_grant: OrgAdminGrant | None = None

    if HELD_RENTER in held and member is not None:
        renter_group = await _get_or_create_group(
            session, tenant_id, GROUP_RENTER, group_role.id
        )
        await _ensure_group_member(session, tenant_id, member.id, renter_group.id)
        prefix = await _ensure_renter_api_key(session, tenant_id, user)
        controls = evaluate_portal_controls(roles=[], group_names=[GROUP_RENTER])
        renter_grant = RenterGrant(
            tenant_membership=True,
            group=GROUP_RENTER,
            api_key_prefix=prefix,
            can_checkout=controls.can_checkout,
            can_see_leases=controls.can_see_leases,
            can_mint_keys=controls.can_mint_keys,
        )

    if HELD_HOST in held and member is not None:
        host_group = await _get_or_create_group(
            session, tenant_id, GROUP_HOST, group_role.id
        )
        await _ensure_group_member(session, tenant_id, member.id, host_group.id)
        host_grant = HostGrant(
            organization_id=host_org_id,
            group=GROUP_HOST,
            device_enrolled=False,
        )

    if HELD_ORG_ADMIN in held and member is not None:
        admin_role = await _get_or_create_role(
            session, tenant_id, _ORG_ADMIN_ROLE_NAME
        )
        member.role_id = admin_role.id
        await session.flush()
        email = _email_norm(user)
        org_admin_grant = OrgAdminGrant(
            portal_role=_ORG_ADMIN_ROLE_NAME,
            email=email,
            network_admin_seed=email == NETWORK_ADMIN_SEED_EMAIL,
            keycloak_bootstrap_admin=False,
        )

    # Device creation belongs to its own workflow. Do not compare tenant-wide
    # counts: an unrelated installer may register a device during this grant.

    granted = tuple(sorted(held))
    return EnrollmentGrantResult(
        granted=granted,
        refused=refused,
        wallet_address=wallet,
        renter=renter_grant,
        host=host_grant,
        org_admin=org_admin_grant,
        device_enrolled=False,
    )
