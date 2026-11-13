from __future__ import annotations

import logging
import secrets
import uuid
from typing import Annotated

import jwt
import httpx

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from controlplane_api.event_types import AUTH_LOGIN_SUCCESS_V1, AUTH_TOKEN_ISSUED_V1
from controlplane_api.exceptions import ForbiddenException
from controlplane_api.config import settings
from auth_service import outbox
from api.domain.operator.population import (
    hosted_domains_from_claims,
    tenant_session_permissions,
)
from api.infrastructure.security.tenant_session_jwt import (
    TTL_SECONDS as TENANT_SESSION_TTL_SECONDS,
    mint_tenant_session_jwt,
    is_smoke_session,
)
from controlplane_events.payloads import AuthLoginSuccessPayload, AuthTokenIssuedPayload

from auth_service.claims import (
    groups_from_claims,
    identity_provider_from_claims,
    tenant_uuid_from_claims,
)
from auth_service.deps import (
    CurrentAuthUser,
    CurrentTenant,
    get_access_token_claims,
    host_setup_claims,
)
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
    SmokeOidcRejected,
    SmokeOidcUnavailable,
    smoke_oidc_enabled,
    verify_github_actions_oidc,
)
from auth_service.siwe import SiweError
from auth_service.siwe_nonces import ChallengeStore, SiweStoreUnavailable
from auth_service.tenant_switch import authorize_tenant_switch
from auth_service.host_setup import authorize_host_setup
from auth_service.token_validation import unsafe_subject_from_token
from auth_service.wallet_bind import bind_wallet, get_wallet_binding, issue_siwe_nonce

from auth_service.connect_session import router as connect_session_router

router = APIRouter(tags=["auth"])
router.include_router(connect_session_router)
from auth_service.scoped_session import router as scoped_session_router
router.include_router(scoped_session_router)
from auth_service.startup_routes import router as startup_router
router.include_router(startup_router)
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
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_exp": False,
            },
        )
    except Exception:
        return {}


@router.post(
    "/login",
    response_model=LoginStartResponse,
    summary="Start OIDC login",
    description="Returns Keycloak authorization URL; optional identity_provider_hint selects broker (Google, Entra, GitHub, …).",
)
async def auth_login(
    body: LoginStartRequest = LoginStartRequest(),
) -> LoginStartResponse:
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

    await outbox.publish_auth_event(
        token=access,
        tenant_id=tid,
        event_type=AUTH_LOGIN_SUCCESS_V1,
        payload=AuthLoginSuccessPayload(
            subject=sub,
            identity_provider=idp,
            tenant_id=tid,
        ).model_dump(mode="json"),
    )
    await outbox.publish_auth_event(
        token=access,
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
    await outbox.publish_auth_event(
        token=access,
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
    if (__import__("os").environ.get("AUTH_SCOPE_GENERATION") or
        __import__("os").environ.get("STARTUP_IDENTITY_ENABLED") == "1"):
        raise HTTPException(403,"Use the explicit scoped-session endpoint",headers={"Cache-Control":"no-store"})
    if is_smoke_session(claims):
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

    from auth_service.test_operator_seed import (
        ensure_seeded_host_role,
        provision_test_operator,
    )

    from auth_service import operator_binding

    try:
        await provision_test_operator(claims, body.tenant_id)
        denial = await ensure_seeded_host_role(claims, body.tenant_id)
        await operator_binding.provision(claims, body.tenant_id)
        if denial:
            raise ForbiddenException(denial)
        grant = await authorize_tenant_switch(user, body.tenant_id)
    except (httpx.HTTPError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, 'Tenant membership authority unavailable',
                            headers={'Cache-Control': 'no-store'}) from exc
    if grant is None:
        raise ForbiddenException("Not a member of this tenant")
    proposed = tenant_session_permissions(
        grant.permissions,
        email=user.email,
        # Tenant-session groups describe that source tenant, not fresh IdP proof.
        groups=groups_from_claims(claims) if not claims.get("spanopticon_auth") else [],
        hosted_domains=hosted_domains_from_claims(claims),
    )
    access = mint_tenant_session_jwt(
        claims={**claims, "permissions": [], "realm_access": {"roles": []}, "groups": list(grant.groups)},
        tenant_id=body.tenant_id,
        extra_roles=[grant.role_name],
        extra_permissions=operator_binding.permissions(
            claims, body.tenant_id, grant.role_name, proposed
        ),
    )
    payload = _unsafe_payload(access)
    sub = unsafe_subject_from_token(access) or user.sub or "unknown"
    await outbox.publish_auth_event(
        token=access,
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
    settings.smoke_session_route,
    response_model=SmokeSessionResponse,
    summary="Mint a test-plane smoke renter session from GitHub OIDC",
    description=(
        "Test plane only. Verifies a GitHub Actions OIDC token for "
        "Environment test, enrolls the configured smoke identity on the marketplace "
        "tenant, and returns a short-lived tenant-session JWT. The smoke "
        "job uses that JWT on the existing api-keys and lease routes. "
        "Not a stored credential. Not a Keycloak admin call. "
        "Off unless the configured enable flag is 1. Startup refuses that flag "
        "when the issuer or host has no .test."
    ),
)
async def auth_smoke_session(
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
    from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
    from auth_service.session_membership import authorize_session_member

    identity = AuthMeResponse(
        sub=settings.smoke_session_subject,
        email=settings.smoke_session_email,
        preferred_username=settings.smoke_session_username,
        roles=["renter"],
        groups=["renter"],
    )
    try:
        granted = await grant_held_roles(
            None,
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
        member = await authorize_session_member(settings.smoke_session_subject, MARKETPLACE_TENANT_ID)
        if member is None:
            return _smoke_json(
                status.HTTP_403_FORBIDDEN,
                "smoke_membership_refused",
                "smoke renter membership refused",
            )

        access = mint_tenant_session_jwt(
            claims={
                "sub": str(member.user_id),
                "email": settings.smoke_session_email,
                "preferred_username": settings.smoke_session_username,
                "azp": settings.smoke_oidc_audience,
                "scope": "openid",
                "smoke_session": True,
                settings.smoke_session_claim: True,
                "realm_access": {"roles": ["renter"]},
                "groups": ["renter"],
            },
            tenant_id=MARKETPLACE_TENANT_ID,
            extra_roles=["renter"],
        )
        await outbox.publish_auth_event(
            token=access,
            tenant_id=MARKETPLACE_TENANT_ID,
            event_type=AUTH_TOKEN_ISSUED_V1,
            payload=AuthTokenIssuedPayload(
                subject=str(member.user_id),
                grant_type=settings.smoke_session_claim,
                client_id=settings.smoke_oidc_audience,
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
        logger.exception("smoke session failed")
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
        user_id=member.user_id,
    )


def siwe_nonce_store(request: Request) -> ChallengeStore:
    store = getattr(request.app.state, "siwe_nonce_store", None)
    if store is None:
        raise HTTPException(503, "SIWE nonce storage is not configured")
    return store


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
    store: ChallengeStore = Depends(siwe_nonce_store),
) -> SiweNonceResponse:
    try:
        issued = await issue_siwe_nonce(
            user, address=body.address, chain_id=body.chain_id, store=store
        )
    except SiweStoreUnavailable:
        raise HTTPException(503, "SIWE nonce storage temporarily unavailable") from None
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
    store: ChallengeStore = Depends(siwe_nonce_store),
    session: AsyncSession = Depends(get_db_session),
) -> WalletBindingResponse:
    try:
        bound = await bind_wallet(
            session, user, message=body.message, signature=body.signature, store=store
        )
    except SiweStoreUnavailable:
        raise HTTPException(503, "SIWE nonce storage temporarily unavailable") from None
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


@router.get("/enrollment/marketplace")
async def enrollment_marketplace() -> dict[str, str]:
    """Public enrollment target; identity and role checks remain on the grant."""
    from controlplane_tenancy.marketplace import MARKETPLACE_TENANT_ID

    return {"tenant_id": str(MARKETPLACE_TENANT_ID)}


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
        "a target-tenant-bound token already has it, and is not granted together with "
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
    from controlplane_tenancy.marketplace import MARKETPLACE_TENANT_ID

    if body.tenant_id != MARKETPLACE_TENANT_ID:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail="Public enrollment is limited to the marketplace tenant")
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


@router.get("/host-setup/me", response_model=AuthMeResponse)
async def host_setup_me(
    claims: Annotated[dict, Depends(host_setup_claims)],
) -> AuthMeResponse:
    return AuthMeResponse(sub=str(claims["sub"]), email=claims.get("email"))


@router.post("/host-setup/enrollment/grant", response_model=EnrollmentGrantResponse)
async def host_setup_grant(
    body: EnrollmentGrantRequest,
    request: Request,
    claims: Annotated[dict, Depends(host_setup_claims)],
    session: AsyncSession = Depends(get_db_session),
) -> EnrollmentGrantResponse:
    if body.held_roles != ["host"]:
        raise ForbiddenException("Host setup can request only host membership")
    user = AuthMeResponse(sub=str(claims["sub"]), email=claims.get("email"))
    return await auth_enrollment_grant(body, request, user, session)


@router.post("/host-setup/session", response_model=TokenBundleResponse)
async def host_setup_session(
    body: SwitchTenantRequest,
    request: Request,
    claims: Annotated[dict, Depends(host_setup_claims)],
) -> TokenBundleResponse:
    from api.infrastructure.security.tenant_session_jwt import mint_host_setup_session

    header = request.headers.get("X-Tenant-ID")
    if header and header != str(body.tenant_id):
        raise ForbiddenException("X-Tenant-ID must match tenant in request body")
    grant = await authorize_host_setup(str(claims["sub"]), body.tenant_id)
    if grant is None:
        raise ForbiddenException("Active unbanned host membership required in this tenant")
    token = mint_host_setup_session(claims=claims, tenant_id=body.tenant_id)
    await outbox.publish_auth_event(
        token=token,
        tenant_id=body.tenant_id,
        event_type=AUTH_TOKEN_ISSUED_V1,
        payload=AuthTokenIssuedPayload(
            subject=str(claims["sub"]),
            grant_type="host_setup",
            client_id="hypermesh-host-setup",
        ).model_dump(mode="json"),
    )
    return TokenBundleResponse(
        access_token=token,
        refresh_token=None,
        expires_in=TENANT_SESSION_TTL_SECONDS,
        token_type="Bearer",
    )

from auth_service.network_session import router as network_session_router
router.include_router(network_session_router)
