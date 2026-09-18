"""Enrollment role-grant job after Keycloak identify + SIWE bind.

Grants only the roles the identified person holds. Reuses the existing
renter group, host organization + host group, and portal admin role.
Membership is an internal users-row write for an existing tenant
(service/repository, not the renter JWT and not POST /api/v1/users).
Does not enroll a device, mint an enroll token, invent a renter role,
or add a payment role.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass

import bcrypt
from sqlalchemy import func, select
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
    HypermeshDevice,
    Organization,
    Role,
    Tenant,
    User,
    UserGroupMembership,
    UserWalletBinding,
)

from auth_service.schemas import AuthMeResponse

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
_HOST_ORG_NAME = "Host"


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


def held_roles_from_identity(
    user: AuthMeResponse,
    requested: list[str] | None = None,
) -> tuple[frozenset[str], tuple[str, ...]]:
    """Return (grantable ∩ held, refused). Requested roles cannot escalate."""
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

    if requested is None:
        return frozenset(token_held), ()

    refused: list[str] = []
    asked: set[str] = set()
    for raw in requested:
        name = str(raw).strip().lower()
        if not name:
            continue
        if name in FORBIDDEN_GRANT_ALIASES or name not in GRANTABLE:
            refused.append(name)
            continue
        asked.add(name)
        if name not in token_held:
            refused.append(name)
    granted = frozenset(asked & token_held)
    return granted, tuple(refused)


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


async def _get_or_create_role(
    session: AsyncSession, tenant_id: uuid.UUID, name: str
) -> Role:
    found = await session.execute(
        select(Role).where(
            Role.tenant_id == tenant_id,
            func.lower(Role.name) == name.lower(),
        )
    )
    role = found.scalar_one_or_none()
    if role is not None:
        return role
    role = Role(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        name=name,
        description=None,
        permissions=[],
    )
    session.add(role)
    await session.flush()
    return role


async def _get_or_create_group(
    session: AsyncSession, tenant_id: uuid.UUID, name: str, role_id: uuid.UUID
) -> Group:
    found = await session.execute(
        select(Group).where(
            Group.tenant_id == tenant_id,
            func.lower(Group.name) == name.lower(),
        )
    )
    group = found.scalar_one_or_none()
    if group is not None:
        return group
    group = Group(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        name=name,
        description=None,
        role_id=role_id,
    )
    session.add(group)
    await session.flush()
    return group


async def _get_or_create_host_org(
    session: AsyncSession, tenant_id: uuid.UUID
) -> Organization:
    found = await session.execute(
        select(Organization)
        .where(Organization.tenant_id == tenant_id)
        .order_by(Organization.created_at.asc())
    )
    org = found.scalars().first()
    if org is not None:
        return org
    org = Organization(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        legal_name=_HOST_ORG_NAME,
    )
    session.add(org)
    await session.flush()
    return org


async def _ensure_membership_user(
    session: AsyncSession, tenant_id: uuid.UUID, user: AuthMeResponse
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
        return row
    first, last = _name_parts(user)
    return await create_tenant_membership_row(
        session,
        tenant_id,
        email=email,
        first_name=first,
        last_name=last,
        gender="unspecified",
        is_active=True,
        keycloak_sub=user.sub,
    )


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


async def _device_count(session: AsyncSession, tenant_id: uuid.UUID) -> int:
    q = await session.execute(
        select(func.count()).select_from(HypermeshDevice).where(
            HypermeshDevice.tenant_id == tenant_id
        )
    )
    return int(q.scalar_one())


async def grant_held_roles(
    session: AsyncSession,
    user: AuthMeResponse,
    *,
    tenant_id: uuid.UUID | None = None,
    requested: list[str] | None = None,
) -> EnrollmentGrantResult:
    """Job: grant only the roles this identified person holds.

    Inserts a ``users`` row for the identified Keycloak person when none
    exists. Default tenant is the marketplace tenant
    ``8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d``.
    """
    if not user.sub or not str(user.sub).strip():
        raise EnrollmentError("Keycloak subject is required")
    tenant_id = tenant_id or MARKETPLACE_TENANT_ID
    await _require_tenant(session, tenant_id)
    await set_current_tenant_id_guc(session, tenant_id)

    held, refused = held_roles_from_identity(user, requested)
    wallet = await _bound_wallet(session, user.sub)
    devices_before = await _device_count(session, tenant_id)

    member: User | None = None
    if held:
        member = await _ensure_membership_user(session, tenant_id, user)

    renter_grant: RenterGrant | None = None
    host_grant: HostGrant | None = None
    org_admin_grant: OrgAdminGrant | None = None

    group_role = await _get_or_create_role(session, tenant_id, _GROUP_ROLE_NAME)

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
        org = await _get_or_create_host_org(session, tenant_id)
        host_group = await _get_or_create_group(
            session, tenant_id, GROUP_HOST, group_role.id
        )
        await _ensure_group_member(session, tenant_id, member.id, host_group.id)
        host_grant = HostGrant(
            organization_id=org.id,
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

    devices_after = await _device_count(session, tenant_id)
    if devices_after != devices_before:
        raise EnrollmentError("host grant must not enroll a device")

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
