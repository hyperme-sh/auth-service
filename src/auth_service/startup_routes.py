"""Default-disabled startup commands and read-only verified login resolution."""
import hmac
import os
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
import httpx
from auth_service import startup_identity as identity
from auth_service._startup_contract import fingerprint
from auth_service.deps import get_access_token_claims

router = APIRouter(prefix='/startup')


class Command(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mapping_sha256: str = Field(pattern='^[a-f0-9]{64}$')


@router.post('/reconcile')
async def reconcile(command: Command, request: Request):
    expected = os.environ.get('AUTH_STARTUP_TOKEN','')
    if not expected or not hmac.compare_digest(request.headers.get('authorization','').encode(),('Bearer '+expected).encode()):
        raise HTTPException(401,'Scoped startup credential required')
    try:
        config = identity.configuration()
        if command.mapping_sha256 != fingerprint(config): raise ValueError('Mapping differs')
        return await identity.reconcile(config)
    except (ValueError,OSError,httpx.HTTPError):
        raise HTTPException(409,'Startup binding unavailable or conflicting') from None


@router.get('/identity')
async def resolve(claims: dict = Depends(get_access_token_claims)):
    try:
        return await identity.resolve(identity.configuration(),claims)
    except (ValueError,OSError,httpx.HTTPError):
        raise HTTPException(403,'Configured startup identity is not available for this login') from None
