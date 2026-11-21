"""Default-disabled startup commands and read-only verified login resolution."""
import hmac
import os
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
import httpx
from jwt import InvalidTokenError, PyJWKClientError
from auth_service import startup_identity as identity
from auth_service._startup_contract import fingerprint
from auth_service.deps import bearer_access_token, get_access_token_claims
from auth_service import startup_github_member
from auth_service.session_membership import MemberAuthorityUnavailable

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
    except (ValueError,OSError,httpx.HTTPError,InvalidTokenError):
        raise HTTPException(403,'Configured startup identity is not available for this login') from None


@router.get('/identity/github-member')
async def resolve_github_member(response: Response, token: str = Depends(bearer_access_token)):
    return await resolve_test_member(response, token, 'github')


@router.get('/identity/nightly-member')
async def resolve_nightly_member(response: Response, token: str = Depends(bearer_access_token)):
    return await resolve_test_member(response, token, startup_github_member.NIGHTLY_PROVIDER)


async def resolve_test_member(response: Response, token: str, provider: str):
    response.headers['Cache-Control'] = 'no-store'
    try:
        return await startup_github_member.resolve(token, provider)
    except (ValueError, OSError, InvalidTokenError, PyJWKClientError, MemberAuthorityUnavailable):
        raise HTTPException(403, 'Configured startup identity is not available for this login',
                            headers={'Cache-Control': 'no-store'}) from None


@router.post('/status')
async def status(command: Command, request: Request):
    expected = os.environ.get('AUTH_STARTUP_READ_TOKEN','')
    if not expected or not hmac.compare_digest(request.headers.get('authorization','').encode(),('Bearer '+expected).encode()):
        raise HTTPException(401,'Scoped startup read credential required')
    try:
        config = identity.configuration()
        if command.mapping_sha256 != fingerprint(config): raise ValueError('Mapping differs')
        return await identity.status(config)
    except (ValueError,OSError,httpx.HTTPError):
        raise HTTPException(409,'Startup binding unavailable or conflicting') from None
