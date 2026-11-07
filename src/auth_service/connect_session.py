"""Private payout issuer facts from two independently verified credentials.

The tenant token supplies tenant authority, never MFA. The original browser
OIDC credential supplies signed authentication time and factor evidence. It is
introspected on every request; neither credential is retained or returned.
"""

import asyncio
import hashlib
import json
import os
import time
import uuid
from datetime import UTC, datetime

import httpx
import jwt
from api.infrastructure.security.keycloak_jwt import get_keycloak_jwt_validator
from api.infrastructure.security.tenant_session_jwt import (
    is_smoke_session,
    try_decode_tenant_session_jwt,
)
from controlplane_api.config import settings
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from auth_service.keycloak_oidc import introspect_access_token
from auth_service.session_membership import authorize_session_member, MemberAuthorityUnavailable

router = APIRouter()
BROWSER_CLIENT = "controlplane-frontend"
MAX_CONNECT_SESSION_AGE_SECONDS = 86400


class SessionDenied(ValueError):
    pass


class MembershipRevoked(SessionDenied):
    """Only raised after both credentials were verified and live membership denied."""


class SessionUnavailable(RuntimeError):
    """The issuer did not supply a usable decision; never revoke from this."""


def introspection_shape(active):
    if not isinstance(active, dict) or type(active.get("active")) is not bool:
        raise SessionUnavailable()
    # RFC 7662 inactive responses may contain only this explicit boolean.
    if active["active"] is False:
        return
    if any(
        not isinstance(active.get(key), str) or not active[key]
        for key in ("sub", "client_id")
    ):
        raise SessionUnavailable()
    for key in ("sid", "session_state"):
        if key in active and (not isinstance(active[key], str) or not active[key]):
            raise SessionUnavailable()


def credential(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 32768
        or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
    ):
        raise SessionDenied()
    return value


def confidential_introspection_credentials():
    # Payout authentication must never reuse the public browser client.
    try:
        client_id = credential(os.getenv("AUTH_CONNECT_INTROSPECTION_CLIENT_ID"))
        secret = credential(os.getenv("AUTH_CONNECT_INTROSPECTION_CLIENT_SECRET"))
    except SessionDenied:
        raise SessionUnavailable() from None
    if client_id == BROWSER_CLIENT:
        raise SessionUnavailable()
    return client_id, secret


def verified_issuer_facts(origin, active, *, now=None):
    """Signed, introspected browser identity; independent of tenant/host roles."""
    now = int(time.time()) if now is None else now
    if (
        not isinstance(origin, dict)
        or not isinstance(active, dict)
        or (
            origin.get("azp") != BROWSER_CLIENT
            or origin.get("iss") != settings.keycloak_issuer.rstrip("/")
            or not isinstance(origin.get("sub"), str)
            or not origin["sub"]
            or active.get("active") is not True
            or active.get("sub") != origin["sub"]
            or active.get("client_id") != BROWSER_CLIENT
        )
    ):
        raise SessionDenied()
    sid = origin.get("sid") or origin.get("session_state")
    if not isinstance(sid, str) or not 1 <= len(sid) <= 512:
        raise SessionDenied()
    # Introspection is bound to this exact token by the issuer request. Refuse
    # contradictory session identity if the issuer includes it in its response.
    for key in ("sid", "session_state"):
        if key in active and active[key] != sid:
            raise SessionDenied()
    for key in ("exp", "iat", "auth_time"):
        if type(origin.get(key)) is not int:
            raise SessionDenied()
    if not 0 < origin["auth_time"] <= origin["iat"] <= now < origin["exp"]:
        raise SessionDenied()
    if now - origin["auth_time"] >= MAX_CONNECT_SESSION_AGE_SECONDS:
        raise SessionDenied()
    # This contract requires a reviewed Keycloak LoA-2 password + OTP flow.
    # No substring matches, refresh timestamps, tenant-token AMR or caller claims.
    methods = origin.get("amr")
    mfa = (
        origin.get("acr") == "2"
        and isinstance(methods, list)
        and all(isinstance(m, str) for m in methods)
        and "pwd" in methods
        and bool({"otp", "totp"}.intersection(methods))
    )
    ref = hashlib.sha256(
        json.dumps(
            [origin["iss"], origin["sub"], sid, origin["auth_time"]],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {
        "max_session_age_seconds": MAX_CONNECT_SESSION_AGE_SECONDS,
        "subject": origin["sub"],
        "session_ref": ref,
        "second_factor_at": datetime.fromtimestamp(origin["auth_time"], UTC).isoformat()
        if mfa
        else None,
        "observed_at": datetime.fromtimestamp(now, UTC).isoformat(),
        "expires_at": datetime.fromtimestamp(origin["exp"], UTC).isoformat(),
    }


def verified_facts(tenant, origin, active, *, now=None):
    if (
        not isinstance(tenant, dict)
        or not isinstance(origin, dict)
        or (
            tenant.get("spanopticon_auth") != "tenant_session"
            or is_smoke_session(tenant)
            or tenant.get("azp") != BROWSER_CLIENT
            or tenant.get("sub") != origin.get("sub")
        )
    ):
        raise SessionDenied()
    return verified_issuer_facts(origin, active, now=now) | {
        "source": "auth_connect_session_v2",
        "tenant_id": str(uuid.UUID(tenant["tenant_id"])),
    }


@router.get("/connect-session-end-context", include_in_schema=False)
async def connect_session_end_context(request: Request):
    """Only ending this verified issuer session: no tenant/owner grants are issued."""
    headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    try:
        original = credential(request.headers.get("x-auth-session-token"))
        origin = await get_keycloak_jwt_validator().validate(original)
        client_id, client_secret = confidential_introspection_credentials()
        async with httpx.AsyncClient(
            timeout=5, trust_env=False, follow_redirects=False
        ) as client:
            try:
                active = await introspect_access_token(
                    original,
                    client=client,
                    client_id=client_id,
                    client_secret=client_secret,
                )
            except (ValueError, TypeError):
                raise SessionUnavailable() from None
        introspection_shape(active)
        facts = verified_issuer_facts(origin, active)
        facts.pop("second_factor_at")
        return JSONResponse(
            facts | {"source": "auth_connect_session_end_v1"}, headers=headers
        )
    except (jwt.InvalidTokenError, SessionDenied, ValueError, KeyError, TypeError):
        return JSONResponse(
            {"detail": "Verified browser session required"},
            status_code=403,
            headers=headers,
        )
    except (SessionUnavailable, httpx.HTTPError, TimeoutError, jwt.PyJWKClientError):
        return JSONResponse(
            {"detail": "Session verification unavailable"},
            status_code=503,
            headers=headers,
        )


async def current_member(tenant_id, subject):
    try:
        grant = await authorize_session_member(subject, tenant_id)
    except MemberAuthorityUnavailable as exc:
        raise SessionUnavailable() from exc
    if grant is None:
        raise MembershipRevoked()
    return str(grant.user_id)


@router.get("/connect-session-context", include_in_schema=False)
async def connect_session_context(request: Request):
    return await session_context(request)


@router.get("/verification-context", include_in_schema=False)
async def verification_context(request: Request):
    return await session_context(request, verification=True)


async def session_context(request: Request, *, verification=False):
    headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    try:
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise SessionDenied()
        tenant = await asyncio.to_thread(try_decode_tenant_session_jwt, credential(authorization[7:]))
        if not tenant:
            raise SessionDenied()
        tid = uuid.UUID(tenant["tenant_id"])
        if uuid.UUID(request.headers.get("x-tenant-id", "")) != tid:
            raise SessionDenied()
        original = credential(request.headers.get("x-auth-session-token"))
        origin = await get_keycloak_jwt_validator().validate(original)
        client_id, client_secret = confidential_introspection_credentials()
        async with httpx.AsyncClient(
            timeout=5, trust_env=False, follow_redirects=False
        ) as client:
            try:
                active = await introspect_access_token(
                    original,
                    client=client,
                    client_id=client_id,
                    client_secret=client_secret,
                )
            except (ValueError, TypeError):
                # Malformed HTTP-200 JSON is an outage, not an identity denial.
                raise SessionUnavailable() from None
        introspection_shape(active)
        facts = verified_facts(tenant, origin, active)
        facts["member_id"] = await current_member(tid, facts["subject"])
        if verification:
            from auth_service.verification_evidence import email_evidence
            facts = facts | email_evidence(origin)
            facts["source"] = "auth_verification_v1"
        return JSONResponse(facts, headers=headers)
    except MembershipRevoked:
        return JSONResponse(
            {
                "detail": "Verified active tenant member required",
                "code": "membership_revoked",
            },
            status_code=403,
            headers=headers,
        )
    except (jwt.InvalidTokenError, SessionDenied, ValueError, KeyError, TypeError):
        return JSONResponse(
            {"detail": "Verified browser session required"},
            status_code=403,
            headers=headers,
        )
    except (
        SessionUnavailable,
        httpx.HTTPError,
        TimeoutError,
        jwt.PyJWKClientError,
    ):
        return JSONResponse(
            {"detail": "Session verification unavailable"},
            status_code=503,
            headers=headers,
        )
