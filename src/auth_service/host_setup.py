"""Host-setup membership is authorized by the user owner, never auth's database."""
import uuid

import httpx
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict
from auth_service import identity_owner


class HostSetupGrant(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    user_id: uuid.UUID


async def authorize_host_setup(subject: str, tenant_id: uuid.UUID) -> HostSetupGrant | None:
    try:
        result = await identity_owner.call('host-setup', subject=subject, tenant_id=str(tenant_id))
        return None if result is None else HostSetupGrant.model_validate(result)
    except (httpx.HTTPError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, 'Host membership authority unavailable') from exc
