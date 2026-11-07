"""Authorize tenant switch from membership or host manage-tenants."""

from __future__ import annotations

import uuid
from dataclasses import dataclass


from controlplane_api.permissions import Permission


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














async def authorize_tenant_switch(user, tenant_id, session=None):
    from auth_service.identity_owner import call
    from pydantic import TypeAdapter
    result = await call('tenant-switch-current', user=user.model_dump(mode='json'), tenant_id=str(tenant_id))
    return None if result is None else TypeAdapter(TenantSwitchGrant).validate_python(result)
