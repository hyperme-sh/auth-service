from __future__ import annotations

import uuid
from typing import Any

from api.core.config import settings


def roles_from_claims(claims: dict[str, Any]) -> list[str]:
    ra = claims.get("realm_access")
    if isinstance(ra, dict):
        roles = ra.get("roles")
        if isinstance(roles, list):
            return [str(r) for r in roles]
    return []


def scopes_from_claims(claims: dict[str, Any]) -> list[str]:
    s = claims.get("scope")
    if isinstance(s, str) and s.strip():
        return s.split()
    return []


def identity_provider_from_claims(claims: dict[str, Any]) -> str | None:
    for key in (
        "idp_alias",
        "identity_provider",
        "brokered_idp_alias",
        "preferred_username",
    ):
        v = claims.get(key)
        if isinstance(v, str) and v:
            return v
    return None


def tenant_uuid_from_claims(claims: dict[str, Any]) -> uuid.UUID | None:
    for name in settings.auth_tenant_claim_name_list():
        raw = claims.get(name)
        if raw is None or raw == "":
            continue
        try:
            return uuid.UUID(str(raw))
        except ValueError:
            continue
    return None


def mfa_satisfied(claims: dict[str, Any]) -> bool:
    if not settings.oidc_require_mfa:
        return True
    amr = claims.get("amr")
    if amr is None:
        return False
    items: list[Any] = amr if isinstance(amr, list) else [amr]
    markers = ("otp", "mfa", "totp", "webauthn")
    for x in items:
        low = str(x).lower()
        if any(m in low for m in markers):
            return True
    return False


def introspection_to_claims(body: dict[str, Any]) -> dict[str, Any]:
    """Normalize Keycloak token introspection JSON to claim-like dict."""
    return dict(body)
