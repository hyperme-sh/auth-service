from __future__ import annotations

import secrets
import uuid
from typing import Annotated

import jwt

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.common.event_types import AUTH_LOGIN_SUCCESS_V1, AUTH_TOKEN_ISSUED_V1
from api.common.exceptions import ForbiddenException
from api.core.config import settings
from api.infrastructure.messaging.tenant_event_publisher import get_tenant_event_publisher
from api.infrastructure.security.tenant_session_jwt import (
    TTL_SECONDS as TENANT_SESSION_TTL_SECONDS,
    mint_tenant_session_jwt,
)
from controlplane_events.payloads import AuthLoginSuccessPayload, AuthTokenIssuedPayload

from auth_service.claims import identity_provider_from_claims, tenant_uuid_from_claims
from auth_service.deps import CurrentAuthUser, CurrentTenant, get_access_token_claims
from auth_service.keycloak_oidc import (
    build_authorization_url,
    exchange_authorization_code,
    refresh_tokens,
)
from auth_service.schemas import (
    AuthMeResponse,
    LoginStartRequest,
    LoginStartResponse,
    RefreshTokenRequest,
    SwitchTenantRequest,
    TokenBundleResponse,
)
from auth_service.tenant_switch import authorize_tenant_switch
from auth_service.token_validation import unsafe_subject_from_token

router = APIRouter(tags=["auth"])


def _unsafe_payload(access_token: str) -> dict:
    try:
        return jwt.decode(
            access_token,
            options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
        )
    except Exception:
        return {}


@router.post(
    "/login",
    response_model=LoginStartResponse,
    summary="Start OIDC login",
    description="Returns Keycloak authorization URL; optional identity_provider_hint selects broker (Google, Entra, GitHub, …).",
)
async def auth_login(body: LoginStartRequest = LoginStartRequest()) -> LoginStartResponse:
    state = secrets.token_urlsafe(32)
    url = build_authorization_url(
        state=state,
        redirect_uri=settings.auth_oidc_redirect_uri,
        identity_provider_hint=body.identity_provider_hint,
    )
    return LoginStartResponse(authorization_url=url, state=state)


@router.get(
    "/callback",
    response_model=TokenBundleResponse,
    summary="OAuth2 authorization code callback",
)
async def auth_callback(code: str, state: str | None = None) -> TokenBundleResponse:
    try:
        bundle = await exchange_authorization_code(
            code, settings.auth_oidc_redirect_uri
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Token exchange failed: {e!s}",
        ) from e

    access = str(bundle.get("access_token") or "")
    refresh = bundle.get("refresh_token")
    if not access:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Token response missing access_token",
        )

    payload = _unsafe_payload(access)
    sub = unsafe_subject_from_token(access) or "unknown"
    tid = tenant_uuid_from_claims(payload)
    idp = identity_provider_from_claims(payload)
    pub = get_tenant_event_publisher()

    await pub.publish(
        tenant_id=tid,
        event_type=AUTH_LOGIN_SUCCESS_V1,
        payload=AuthLoginSuccessPayload(
            subject=sub,
            identity_provider=idp,
            tenant_id=tid,
        ).model_dump(mode="json"),
    )
    await pub.publish(
        tenant_id=tid,
        event_type=AUTH_TOKEN_ISSUED_V1,
        payload=AuthTokenIssuedPayload(
            subject=sub,
            grant_type="authorization_code",
            client_id=settings.keycloak_client_id,
        ).model_dump(mode="json"),
    )

    return TokenBundleResponse(
        access_token=access,
        refresh_token=str(refresh) if refresh else None,
        expires_in=bundle.get("expires_in"),
        token_type=str(bundle.get("token_type") or "Bearer"),
    )


@router.post(
    "/refresh",
    response_model=TokenBundleResponse,
    summary="Refresh access token",
)
async def auth_refresh(body: RefreshTokenRequest) -> TokenBundleResponse:
    try:
        bundle = await refresh_tokens(body.refresh_token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Refresh failed: {e!s}",
        ) from e
    access = str(bundle.get("access_token") or "")
    if not access:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Token response missing access_token",
        )
    payload = _unsafe_payload(access)
    sub = unsafe_subject_from_token(access) or "unknown"
    tid = tenant_uuid_from_claims(payload)
    await get_tenant_event_publisher().publish(
        tenant_id=tid,
        event_type=AUTH_TOKEN_ISSUED_V1,
        payload=AuthTokenIssuedPayload(
            subject=sub,
            grant_type="refresh_token",
            client_id=settings.keycloak_client_id,
        ).model_dump(mode="json"),
    )
    return TokenBundleResponse(
        access_token=access,
        refresh_token=str(bundle["refresh_token"])
        if bundle.get("refresh_token")
        else None,
        expires_in=bundle.get("expires_in"),
        token_type=str(bundle.get("token_type") or "Bearer"),
    )


@router.post(
    "/switch-tenant",
    response_model=TokenBundleResponse,
    summary="Attach tenant_id to a session JWT after membership",
    description=(
        "Keycloak / M2M tokens have no tenant claim. After the actor is a "
        "member of the tenant (or has HOST_MANAGE_TENANTS), this mints a "
        "short-lived session JWT that carries tenant_id. "
        "X-Tenant-ID alone is not enough — do not use this to weaken mint."
    ),
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def auth_switch_tenant(
    body: SwitchTenantRequest,
    request: Request,
    user: CurrentAuthUser,
    claims: Annotated[dict, Depends(get_access_token_claims)],
) -> TokenBundleResponse:
    raw = request.headers.get("X-Tenant-ID")
    if raw:
        try:
            hdr = uuid.UUID(str(raw))
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid X-Tenant-ID",
            ) from e
        if hdr != body.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="X-Tenant-ID must match tenant in request body",
            )

    grant = await authorize_tenant_switch(user, body.tenant_id)
    if grant is None:
        raise ForbiddenException("Not a member of this tenant")

    access = mint_tenant_session_jwt(
        claims=claims,
        tenant_id=body.tenant_id,
        extra_roles=[grant.role_name],
    )
    payload = _unsafe_payload(access)
    sub = unsafe_subject_from_token(access) or user.sub or "unknown"
    await get_tenant_event_publisher().publish(
        tenant_id=body.tenant_id,
        event_type=AUTH_TOKEN_ISSUED_V1,
        payload=AuthTokenIssuedPayload(
            subject=sub,
            grant_type="tenant_switch",
            client_id=str(payload.get("azp") or settings.keycloak_client_id),
        ).model_dump(mode="json"),
    )
    return TokenBundleResponse(
        access_token=access,
        refresh_token=None,
        expires_in=TENANT_SESSION_TTL_SECONDS,
        token_type="Bearer",
    )


@router.get(
    "/me",
    response_model=AuthMeResponse,
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def auth_me(user: CurrentAuthUser) -> AuthMeResponse:
    return user


@router.get(
    "/tenant",
    response_model=dict,
    summary="Example route using get_current_tenant dependency",
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def auth_tenant_probe(tenant_id: CurrentTenant) -> dict:
    return {"tenant_id": str(tenant_id)}
