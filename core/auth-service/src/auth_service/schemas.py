from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field

from auth_service.claims import (
    groups_from_claims,
    identity_provider_from_claims,
    roles_from_claims,
    scopes_from_claims,
    tenant_uuid_from_claims,
)


class LoginStartRequest(BaseModel):
    identity_provider_hint: str | None = Field(
        default=None,
        description="Keycloak broker alias (e.g. google, github, microsoft) passed as kc_idp_hint.",
    )


class LoginStartResponse(BaseModel):
    authorization_url: str
    state: str = Field(description="CSRF/state value; echo to /auth/callback.")


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class TokenBundleResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    expires_in: int | None = None
    token_type: str = "Bearer"


class AuthMeResponse(BaseModel):
    sub: str
    email: str | None = None
    preferred_username: str | None = None
    tenant_id: uuid.UUID | None = None
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(
        default_factory=list,
        description="Keycloak / token groups. Same membership tree as Panopticon groups.",
    )
    scopes: list[str] = Field(default_factory=list)

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> AuthMeResponse:
        email = claims.get("email")
        if email is None:
            email = claims.get("preferred_username")
        if email is None:
            email = claims.get("username")
        return cls(
            sub=str(claims.get("sub") or ""),
            email=str(email) if email else None,
            preferred_username=str(claims["preferred_username"])
            if claims.get("preferred_username")
            else None,
            tenant_id=tenant_uuid_from_claims(claims),
            roles=roles_from_claims(claims),
            groups=groups_from_claims(claims),
            scopes=scopes_from_claims(claims),
        )
