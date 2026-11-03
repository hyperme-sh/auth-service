from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from controlplane_api.exceptions import ForbiddenException, UnauthorizedException
from auth_service.claims import mfa_satisfied, tenant_uuid_from_claims
from auth_service.schemas import AuthMeResponse
from auth_service.token_validation import validate_access_token

http_bearer = HTTPBearer(auto_error=False)


async def bearer_access_token(
    creds: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(http_bearer),
    ],
) -> str:
    if creds is None or not creds.credentials:
        raise UnauthorizedException("Not authenticated")
    return creds.credentials


async def get_access_token_claims(
    token: Annotated[str, Depends(bearer_access_token)],
) -> dict:
    claims = await validate_access_token(token)
    if not mfa_satisfied(claims):
        raise ForbiddenException("MFA is required for this resource")
    return claims


async def get_current_auth_user(
    claims: Annotated[dict, Depends(get_access_token_claims)],
) -> AuthMeResponse:
    return AuthMeResponse.from_claims(claims)


async def get_current_tenant(
    claims: Annotated[dict, Depends(get_access_token_claims)],
) -> uuid.UUID:
    tid = tenant_uuid_from_claims(claims)
    if tid is None:
        raise ForbiddenException("Missing tenant context in access token")
    return tid


CurrentAuthUser = Annotated[AuthMeResponse, Depends(get_current_auth_user)]
CurrentTenant = Annotated[uuid.UUID, Depends(get_current_tenant)]

# Aliases for app code / imports matching common FastAPI naming.
get_current_user = get_current_auth_user
CurrentUser = CurrentAuthUser


async def host_setup_claims(token: Annotated[str, Depends(bearer_access_token)]) -> dict:
    from api.infrastructure.security.keycloak_jwt import get_keycloak_jwt_validator

    try:
        claims = await get_keycloak_jwt_validator().validate_host_setup(token)
    except Exception as exc:
        raise UnauthorizedException("Invalid host setup identity") from exc
    if not mfa_satisfied(claims):
        raise ForbiddenException("MFA is required for this resource")
    return claims
