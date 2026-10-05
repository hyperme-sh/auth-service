from __future__ import annotations

from typing import Any

import jwt
from jwt import InvalidTokenError

from controlplane_api.exceptions import UnauthorizedException
from controlplane_api.config import settings
from api.infrastructure.security.api_key_exchange_jwt import try_decode_api_key_session_jwt
from api.infrastructure.security.keycloak_jwt import get_keycloak_jwt_validator
from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt

from auth_service.claims import introspection_to_claims
from auth_service.keycloak_oidc import introspect_access_token


async def validate_access_token(access_token: str) -> dict[str, Any]:
    ex = try_decode_api_key_session_jwt(access_token)
    if ex is not None:
        return ex
    switched = try_decode_tenant_session_jwt(access_token)
    if switched is not None:
        return switched

    if settings.auth_token_validation_mode == "introspection":
        body = await introspect_access_token(access_token)
        if not body.get("active") or body.get("azp") == "hypermesh-host-setup" or body.get("client_id") == "hypermesh-host-setup":
            raise UnauthorizedException("Invalid or inactive access token")
        return introspection_to_claims(body)

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
