from __future__ import annotations

import asyncio
from typing import Any

import jwt
from jwt import InvalidTokenError

from controlplane_api.exceptions import UnauthorizedException
from controlplane_api.config import settings
from controlplane_identity.account_lifecycle import require_open_account
from controlplane_identity.security.keycloak_jwt import (
    _INTERACTIVE_AGE_CLIENTS, _age_confirmation_satisfied,
)
from api.infrastructure.security.api_key_exchange_jwt import try_decode_api_key_session_jwt
from api.infrastructure.security.keycloak_jwt import get_keycloak_jwt_validator
from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt

from auth_service.claims import introspection_to_claims
from auth_service.keycloak_oidc import introspect_access_token


async def validate_access_token(access_token: str) -> dict[str, Any]:
    ex = await asyncio.to_thread(try_decode_api_key_session_jwt, access_token)
    if ex is not None:
        return ex
    switched = await asyncio.to_thread(try_decode_tenant_session_jwt, access_token)
    if switched is not None:
        return switched

    if settings.auth_token_validation_mode == "introspection":
        body = await introspect_access_token(access_token)
        if not body.get("active") or body.get("azp") == "hypermesh-host-setup" or body.get("client_id") == "hypermesh-host-setup":
            raise UnauthorizedException("Invalid or inactive access token")
        claims = introspection_to_claims(body)
        # Match the trusted JWKS path before applying any service-age exemption.
        presented = [
            claims.get(name) for name in ("azp", "client_id")
            if isinstance(claims.get(name), str) and claims.get(name)
        ]
        allowed = settings.keycloak_allowed_azp_set()
        if any(client not in allowed for client in presented):
            raise UnauthorizedException("Invalid or inactive access token")
        if any(client in _INTERACTIVE_AGE_CLIENTS for client in presented) and not _age_confirmation_satisfied(claims):
            raise UnauthorizedException("Age confirmation required")
        try:
            await asyncio.to_thread(require_open_account, claims)
        except InvalidTokenError as exc:
            raise UnauthorizedException("Invalid or expired access token") from exc
        return claims

    validator = get_keycloak_jwt_validator()
    try:
        return await validator.validate(access_token)
    except InvalidTokenError as e:
        raise UnauthorizedException("Invalid or expired access token") from e
    except Exception as e:
        raise UnauthorizedException("Invalid or expired access token") from e


def unsafe_subject_from_token(access_token: str) -> str | None:
    """Decode JWT payload without verification (event correlation only)."""
    try:
        payload = jwt.decode(
            access_token,
            options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
        )
        sub = payload.get("sub")
        return str(sub) if sub else None
    except Exception:
        return None
