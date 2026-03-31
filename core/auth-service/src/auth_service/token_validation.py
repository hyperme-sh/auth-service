from __future__ import annotations

from typing import Any

import jwt
from jwt import InvalidTokenError

from api.common.exceptions import UnauthorizedException
from api.core.config import settings
from api.infrastructure.security.keycloak_jwt import get_keycloak_jwt_validator

from auth_service.claims import introspection_to_claims
from auth_service.keycloak_oidc import introspect_access_token


async def validate_access_token(access_token: str) -> dict[str, Any]:
    if settings.auth_token_validation_mode == "introspection":
        body = await introspect_access_token(access_token)
        if not body.get("active"):
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
