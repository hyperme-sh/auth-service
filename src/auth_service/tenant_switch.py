"""Authorize tenant switch from membership or host manage-tenants."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from controlplane_api.permissions import Permission
from api.infrastructure.persistence.db_session import get_db_session
from api.infrastructure.persistence.tenant_guc import set_current_tenant_id_guc
from controlplane_db.models import Group, Role, Tenant, User, UserGroupMembership

from auth_service.schemas import AuthMeResponse

_HOST_PERMS = frozenset(
    {
        Permission.HOST_MANAGE_TENANTS.value,
        Permission.FULL_ACCESS.value,
    }
)


@dataclass(frozen=True, slots=True)
class TenantSwitchGrant:
    role_name: str
    permissions: tuple[str, ...] = ()
    user_id: uuid.UUID | None = None
    groups: tuple[str, ...] = ()


async def _target_groups(session: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID | None) -> tuple[str, ...]:
    if user_id is None:
        return ()
    names = await session.scalars(select(Group.name).join(
        UserGroupMembership, UserGroupMembership.group_id == Group.id,
    ).where(
        Group.tenant_id == tenant_id,
        UserGroupMembership.tenant_id == tenant_id,
        UserGroupMembership.user_id == user_id,
    ))
    return tuple(sorted(set(names.all())))


def _role_permissions(role: Role | None) -> tuple[str, ...]:
    if role is None:
        return ()
    return tuple(str(p) for p in (role.permissions or []) if str(p).strip())


def _email_norm(user: AuthMeResponse) -> str | None:
    if not user.email:
        return None
    n = str(user.email).strip().lower()
    return n or None


def _role_has_host_manage(role: Role | None) -> bool:
    if role is None:
        return False
    values = {str(p) for p in (role.permissions or [])}
    return bool(values & _HOST_PERMS)


async def _user_by_email_or_sub(
    session: AsyncSession,
    *,
    email: str | None,
    sub: str | None,
    platform: bool,
    tenant_id: uuid.UUID | None = None,
) -> User | None:
    if email:
        stmt = select(User).where(
            func.lower(User.email) == email,
            User.deleted_at.is_(None),
        )
        if platform:
            stmt = stmt.where(User.tenant_id.is_(None))
        elif tenant_id is not None:
            stmt = stmt.where(User.tenant_id == tenant_id)
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is not None:
            if row.keycloak_sub and row.keycloak_sub != sub:
                return None
            return row
    if sub:
        stmt = select(User).where(
            User.keycloak_sub == sub,
            User.deleted_at.is_(None),
        )
        if platform:
            stmt = stmt.where(User.tenant_id.is_(None))
        elif tenant_id is not None:
            stmt = stmt.where(User.tenant_id == tenant_id)
        return (await session.execute(stmt)).scalar_one_or_none()
    return None


async def _role_for(session: AsyncSession, user: User) -> Role | None:
    if user.role_id is None:
        return None
    stmt = select(Role).where(Role.id == user.role_id)
    if user.tenant_id is None:
        stmt = stmt.where(Role.tenant_id.is_(None))
    else:
        stmt = stmt.where(Role.tenant_id == user.tenant_id)
    return (await session.execute(stmt)).scalar_one_or_none()


async def authorize_tenant_switch(
    user: AuthMeResponse,
    tenant_id: uuid.UUID,
    session: AsyncSession | None = None,
) -> TenantSwitchGrant | None:
    """Allow switch when the actor is a tenant member or a host admin.

    RLS: tenant GUC sees membership rows; empty GUC sees platform
    ``HOST_MANAGE_TENANTS``. Tenant registry is not RLS-scoped.
    """
    db = session or get_db_session()
    exists = await db.execute(select(Tenant.id).where(Tenant.id == tenant_id))
    if exists.scalar_one_or_none() is None:
        return None

    email = _email_norm(user)
    sub = user.sub.strip() if user.sub else None

    await set_current_tenant_id_guc(db, tenant_id)
    member = await _user_by_email_or_sub(
        db, email=email, sub=sub, platform=False, tenant_id=tenant_id
    )
    if member is not None:
        if not member.is_active:
            return None
        role = await _role_for(db, member)
        if role is None:
            return None
        if role and role.name in {"test-network-operator", "entra-network-operator"} and member.keycloak_sub != sub:
            return None
        return TenantSwitchGrant(
            role_name=role.name,
            permissions=_role_permissions(role),
            user_id=getattr(member, "id", None),
            groups=await _target_groups(db, tenant_id, getattr(member, "id", None)),
        )

    await set_current_tenant_id_guc(db, None)
    platform_user = await _user_by_email_or_sub(
        db, email=email, sub=sub, platform=True
    )
    if platform_user is None or not platform_user.is_active:
        return None
    role = await _role_for(db, platform_user)
    if _role_has_host_manage(role):
        return TenantSwitchGrant(
            role_name=role.name,
            permissions=_role_permissions(role),
            user_id=getattr(platform_user, "id", None),
        )
    return None
