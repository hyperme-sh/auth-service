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


def groups_from_claims(claims: dict[str, Any]) -> list[str]:
    """Keycloak group paths or names on the access token. Not a second tree."""
    raw = claims.get("groups")
    if raw is None:
        raw = claims.get("group")
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    if isinstance(raw, list):
        return [str(g).strip() for g in raw if str(g).strip()]
    return []


def scopes_from_claims(claims: dict[str, Any]) -> list[str]:
    s = claims.get("scope")
    if isinstance(s, str) and s.strip():
        return s.split()
    return []


# Microsoft personal accounts. Not an organization tenant.
MSA_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad"
# Entra directory role template: Global Administrator.
ENTRA_GLOBAL_ADMIN_WID = "62e90394-69f5-4237-9190-012177145e10"


def _claim_text(value: Any) -> str:
    return str(value).strip() if isinstance(value, str) else ""


def _claim_list(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def idp_facts_from_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """Broker facts already on the access token. No operator map.

    Keycloak copies the broker alias to ``idp_provider``, the Entra tenant or
    Google hosted domain to ``idp_org``, and directory role ids to ``idp_wids``.
    Raw ``tid``, ``hd``, ``wids``, and ``orgs`` claims are accepted too.
    """
    tid = _claim_text(claims.get("tid"))
    hosted = _claim_text(claims.get("hd"))
    copied_org = _claim_text(claims.get("idp_org"))
    orgs = _claim_list(claims.get("orgs"))
    wids = [
        item.lower()
        for item in _claim_list(claims.get("wids") or claims.get("idp_wids"))
    ]
    provider = _claim_text(
        claims.get("idp_provider")
        or claims.get("identity_provider")
        or claims.get("idp_alias")
    ).lower()
    org = ""
    if not provider:
        if tid or wids:
            provider = "microsoft"
        elif hosted:
            provider = "google"
        elif orgs:
            provider = "github"
    if provider == "microsoft":
        org = tid or copied_org
    elif provider == "google":
        org = hosted or copied_org
    elif provider == "github":
        if not orgs and copied_org:
            orgs = [copied_org]
        org = orgs[0] if orgs else ""
    if provider not in {"microsoft", "google", "github"}:
        provider = ""
    account = "individual"
    if provider == "microsoft" and org and org.lower() != MSA_TENANT_ID:
        account = "organization"
    elif provider == "google" and org:
        account = "organization"
    elif provider == "github" and org:
        account = "organization"
    else:
        org = ""
    return {
        "idp_provider": provider or None,
        "idp_org": org or None,
        "idp_orgs": orgs,
        "idp_wids": wids,
        "idp_account": account if provider else None,
    }


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
    if claims.get("panopticon_auth") in ("api_key", "tenant_session"):
        return True
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
