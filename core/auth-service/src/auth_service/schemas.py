from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field

from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID

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


class SwitchTenantRequest(BaseModel):
    tenant_id: uuid.UUID = Field(
        description="Tenant to put on the access token after membership (or host manage) is verified.",
    )


class SiweNonceRequest(BaseModel):
    address: str = Field(description="EIP-55 or hex wallet the identified person will sign.")
    chain_id: int = Field(default=1, ge=1)


class SiweNonceResponse(BaseModel):
    nonce: str
    issued_at: str
    domain: str
    uri: str
    statement: str
    version: str
    chain_id: int
    message: str


class SiweBindRequest(BaseModel):
    message: str = Field(description="EIP-4361 SIWE message. Signature is verified, not stored.")
    signature: str = Field(description="personal_sign of message. Never persisted.")


class WalletBindingResponse(BaseModel):
    keycloak_sub: str
    email: str | None = None
    wallet_address: str
    bound: bool = True


class EnrollmentGrantRequest(BaseModel):
    tenant_id: uuid.UUID = Field(
        default=MARKETPLACE_TENANT_ID,
        description=(
            "Existing marketplace tenant "
            "(8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d). The grant job INSERTs a "
            "users row as the service. Not POST /api/v1/users as the renter, "
            "and not POST /api/v1/tenants/."
        ),
    )
    held_roles: list[str] | None = Field(
        default=None,
        description="Roles this person holds. Grant is the intersection with the Keycloak token.",
    )


class EnrollmentGrantResponse(BaseModel):
    granted: list[str]
    refused: list[str]
    wallet_address: str | None = None
    device_enrolled: bool = False
    renter: dict | None = None
    host: dict | None = None
    org_admin: dict | None = None


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
