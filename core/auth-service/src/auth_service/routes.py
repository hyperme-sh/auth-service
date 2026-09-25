from __future__ import annotations

import logging
import secrets
import uuid
from typing import Annotated

import jwt

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from api.common.event_types import AUTH_LOGIN_SUCCESS_V1, AUTH_TOKEN_ISSUED_V1
from api.common.exceptions import ForbiddenException
from api.core.config import settings
from api.infrastructure.messaging.tenant_event_publisher import get_tenant_event_publisher
from api.domain.operator.population import (
    hosted_domains_from_claims,
    tenant_session_permissions,
)
from api.infrastructure.security.tenant_session_jwt import (
    TTL_SECONDS as TENANT_SESSION_TTL_SECONDS,
    mint_tenant_session_jwt,
)
from controlplane_events.payloads import AuthLoginSuccessPayload, AuthTokenIssuedPayload

from auth_service.claims import (
    groups_from_claims,
    identity_provider_from_claims,
    tenant_uuid_from_claims,
)
from auth_service.deps import CurrentAuthUser, CurrentTenant, get_access_token_claims
from auth_service.keycloak_oidc import (
    build_authorization_url,
    exchange_authorization_code,
    refresh_tokens,
)
from api.infrastructure.persistence.db_session import get_db_session

from auth_service.enrollment import EnrollmentError, grant_held_roles
from auth_service.schemas import (
    AuthMeResponse,
    EnrollmentGrantRequest,
    EnrollmentGrantResponse,
    LoginStartRequest,
    LoginStartResponse,
    RefreshTokenRequest,
    SiweBindRequest,
    SiweNonceRequest,
    SiweNonceResponse,
    SmokeSessionResponse,
    SwitchTenantRequest,
    TokenBundleResponse,
    WalletBindingResponse,
)
from auth_service.smoke_oidc import (
    SMOKE_EMAIL,
    SMOKE_KEYCLOAK_SUB,
    SmokeOidcRejected,
    SmokeOidcUnavailable,
    smoke_oidc_enabled,
    verify_github_actions_oidc,
)
from auth_service.siwe import SiweError
from auth_service.tenant_switch import authorize_tenant_switch
from auth_service.token_validation import unsafe_subject_from_token
from auth_service.wallet_bind import bind_wallet, get_wallet_binding, issue_siwe_nonce

router = APIRouter(tags=["auth"])
logger = logging.getLogger(__name__)


def _smoke_json(
    status_code: int,
    code: str,
    detail: str,
    *,
    error: str | None = None,
) -> JSONResponse:
    """Typed smoke failure. ``error`` is an exception class name, never a message."""

    body: dict[str, str] = {"detail": detail, "code": code}
    if error:
        body["error"] = error
    return JSONResponse(status_code=status_code, content=body)


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
        "short-lived session JWT that carries tenant_id and the role's "
        "permissions. The pan-test admin seed also receives operator claims. "
        "Inside OPERATOR_OIDC_DOMAIN, OPERATOR_OIDC_GROUP_MAP and "
        "OPERATOR_OIDC_USER_MAP add operator and owner claims. "
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
    if claims.get("hypermesh_smoke") is True:
        raise ForbiddenException("Smoke session cannot switch tenant")
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
    if grant.user_id is not None:
        from api.domain.operator.bans import ban_book

        if not ban_book().user_may_enter(body.tenant_id, grant.user_id):
            raise ForbiddenException("This user is banned from the tenant")

    access = mint_tenant_session_jwt(
        claims=claims,
        tenant_id=body.tenant_id,
        extra_roles=[grant.role_name],
        extra_permissions=tenant_session_permissions(
            grant.permissions,
            email=user.email,
            groups=groups_from_claims(claims),
            hosted_domains=hosted_domains_from_claims(claims),
        ),
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


def _bearer_token(request: Request) -> str:
    raw = request.headers.get("Authorization") or ""
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GitHub OIDC token required",
        )
    return token.strip()


@router.post(
    "/hypermesh-smoke/session",
    response_model=SmokeSessionResponse,
    summary="Mint a test-plane smoke renter session from GitHub OIDC",
    description=(
        "Test plane only. Verifies a GitHub Actions OIDC token for "
        "Environment test, enrolls hypermesh-smoke on the marketplace "
        "tenant, and returns a short-lived tenant-session JWT. The smoke "
        "job uses that JWT on the existing api-keys and lease routes. "
        "Not a stored credential. Not a Keycloak admin call. "
        "Off unless HYPERMESH_SMOKE_OIDC=1. Startup refuses that flag "
        "when the issuer or host has no .test."
    ),
)
async def auth_hypermesh_smoke_session(
    request: Request,
) -> SmokeSessionResponse | JSONResponse:
    # Flag and token checks run before the database. A disabled route stays
    # 404, and a rejected OIDC token stays 401, with no session opened.
    if not smoke_oidc_enabled():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    token = _bearer_token(request)
    try:
        verify_github_actions_oidc(token)
    except SmokeOidcUnavailable:
        return _smoke_json(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "github_jwks_unreachable",
            "GitHub OIDC JWKS unreachable",
        )
    except SmokeOidcRejected:
        return _smoke_json(
            status.HTTP_401_UNAUTHORIZED,
            "github_oidc_rejected",
            "GitHub OIDC token rejected",
        )
    session = get_db_session()

    from api.infrastructure.persistence.tenant_membership import (
        MARKETPLACE_TENANT_ID,
        get_tenant_membership_row,
    )

    identity = AuthMeResponse(
        sub=SMOKE_KEYCLOAK_SUB,
        email=SMOKE_EMAIL,
        preferred_username="hypermesh-smoke",
        roles=["renter"],
        groups=["renter"],
    )
    try:
        granted = await grant_held_roles(
            session,
            identity,
            tenant_id=MARKETPLACE_TENANT_ID,
            requested=["renter"],
        )
        if granted.refused:
            return _smoke_json(
                status.HTTP_403_FORBIDDEN,
                "smoke_enrollment_refused",
                "smoke renter enrollment refused",
            )
        member = await get_tenant_membership_row(
            session,
            MARKETPLACE_TENANT_ID,
            email=SMOKE_EMAIL,
            keycloak_sub=SMOKE_KEYCLOAK_SUB,
        )
        if member is None:
            return _smoke_json(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "smoke_membership_missing",
                "smoke renter membership missing",
            )
        from api.domain.operator.bans import ban_book

        if not ban_book().user_may_enter(MARKETPLACE_TENANT_ID, member.id):
            raise ForbiddenException("This user is banned from the tenant")

        access = mint_tenant_session_jwt(
            claims={
                "sub": str(member.id),
                "email": SMOKE_EMAIL,
                "preferred_username": "hypermesh-smoke",
                "azp": "hypermesh-gateway-smoke",
                "scope": "openid",
                "hypermesh_smoke": True,
                "realm_access": {"roles": ["renter"]},
                "groups": ["renter"],
            },
            tenant_id=MARKETPLACE_TENANT_ID,
            extra_roles=["renter"],
        )
        await get_tenant_event_publisher().publish(
            tenant_id=MARKETPLACE_TENANT_ID,
            event_type=AUTH_TOKEN_ISSUED_V1,
            payload=AuthTokenIssuedPayload(
                subject=str(member.id),
                grant_type="hypermesh_smoke",
                client_id="hypermesh-gateway-smoke",
            ).model_dump(mode="json"),
        )
    except EnrollmentError:
        return _smoke_json(
            status.HTTP_400_BAD_REQUEST,
            "smoke_enrollment_failed",
            "smoke renter enrollment failed",
        )
    except ForbiddenException:
        raise
    except Exception as exc:
        # Class name only. The message can carry a SQL row or a token.
        logger.exception("hypermesh smoke session failed")
        return _smoke_json(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "smoke_session_failed",
            "smoke session failed",
            error=type(exc).__name__,
        )
    return SmokeSessionResponse(
        access_token=access,
        expires_in=TENANT_SESSION_TTL_SECONDS,
        token_type="Bearer",
        tenant_id=MARKETPLACE_TENANT_ID,
        user_id=member.id,
    )


@router.post(
    "/siwe/nonce",
    response_model=SiweNonceResponse,
    summary="Issue an EIP-4361 nonce for the identified Keycloak person",
    description=(
        "Keycloak OIDC remains the login. This nonce is only for binding one "
        "wallet to that same person. Password grant stays off."
    ),
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def auth_siwe_nonce(
    body: SiweNonceRequest,
    user: CurrentAuthUser,
) -> SiweNonceResponse:
    try:
        issued = issue_siwe_nonce(user, address=body.address, chain_id=body.chain_id)
    except SiweError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    return SiweNonceResponse(
        nonce=issued.nonce,
        issued_at=issued.issued_at,
        domain=issued.domain,
        uri=issued.uri,
        statement=issued.statement,
        version=issued.version,
        chain_id=issued.chain_id,
        message=issued.message,
    )


@router.post(
    "/siwe/bind",
    response_model=WalletBindingResponse,
    summary="Bind one SIWE wallet onto the identified Keycloak person",
    description=(
        "Verifies EIP-4361 and stores the recovered address only. "
        "Not a second login. Signature is not stored or returned."
    ),
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def auth_siwe_bind(
    body: SiweBindRequest,
    user: CurrentAuthUser,
    session: AsyncSession = Depends(get_db_session),
) -> WalletBindingResponse:
    try:
        bound = await bind_wallet(
            session, user, message=body.message, signature=body.signature
        )
    except SiweError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    return WalletBindingResponse(
        keycloak_sub=bound.keycloak_sub,
        email=bound.email,
        wallet_address=bound.wallet_address,
        bound=True,
    )


@router.get(
    "/siwe/me",
    response_model=WalletBindingResponse,
    summary="Wallet bound to the identified Keycloak person",
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def auth_siwe_me(
    user: CurrentAuthUser,
    session: AsyncSession = Depends(get_db_session),
) -> WalletBindingResponse:
    bound = await get_wallet_binding(session, user.sub)
    if bound is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No wallet bound")
    return WalletBindingResponse(
        keycloak_sub=bound.keycloak_sub,
        email=bound.email,
        wallet_address=bound.wallet_address,
        bound=True,
    )


@router.post(
    "/enrollment/grant",
    response_model=EnrollmentGrantResponse,
    summary="Add renter or host, then INSERT marketplace membership",
    description=(
        "Workflow/job after Keycloak identify + SIWE bind. Membership is an "
        "internal users-row write for the existing tenant (service, not the "
        "renter JWT). Not POST /api/v1/users self-join. Not POST /api/v1/tenants/. "
        "May add renter or host for the identified person, then INSERT the "
        "marketplace users row and those groups. Org admin is not added unless "
        "the Keycloak token already has it, and is not granted together with "
        "renter/host (invite stays POST /api/v1/users). "
        "No new events. No printed tokens."
    ),
    openapi_extra={"security": [{"BearerAuth": []}]},
)
async def auth_enrollment_grant(
    body: EnrollmentGrantRequest,
    request: Request,
    user: CurrentAuthUser,
    session: AsyncSession = Depends(get_db_session),
) -> EnrollmentGrantResponse:
    raw = request.headers.get("X-Tenant-ID")
    if raw:
        try:
            hdr = uuid.UUID(str(raw))
        except ValueError as e:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail="Invalid X-Tenant-ID"
            ) from e
        if hdr != body.tenant_id:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="X-Tenant-ID must match tenant in request body",
            )
    try:
        result = await grant_held_roles(
            session,
            user,
            tenant_id=body.tenant_id,
            requested=body.held_roles,
        )
    except EnrollmentError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    public = result.as_public_dict()
    return EnrollmentGrantResponse.model_validate(public)


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
