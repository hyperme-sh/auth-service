"""Current member decisions from the user owner, without browser credentials."""
import uuid

import httpx
from pydantic import BaseModel, ConfigDict
from auth_service import identity_owner


class MemberAuthorityUnavailable(RuntimeError):
    pass


class MemberGrant(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    user_id: uuid.UUID


async def authorize_session_member(subject: str, tenant_id: uuid.UUID) -> MemberGrant | None:
    try:
        result = await identity_owner.call('session-member', subject=subject, tenant_id=str(tenant_id))
        return None if result is None else MemberGrant.model_validate(result)
    except (httpx.HTTPError, ValueError, RuntimeError) as exc:
        raise MemberAuthorityUnavailable('Membership authority unavailable') from exc
