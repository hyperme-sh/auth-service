from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import httpx

from api.core.config import settings


def _issuer_base() -> str:
    return (settings.keycloak_issuer or "").rstrip("/")


def token_endpoint_url() -> str:
    return f"{_issuer_base()}/protocol/openid-connect/token"


def authorization_endpoint_url() -> str:
    return f"{_issuer_base()}/protocol/openid-connect/auth"


def introspection_endpoint_url() -> str:
    return f"{_issuer_base()}/protocol/openid-connect/token/introspect"


def build_authorization_url(
    *,
    state: str,
    redirect_uri: str,
    identity_provider_hint: str | None = None,
    scope: str = "openid profile email",
) -> str:
    q: dict[str, str] = {
        "client_id": settings.keycloak_client_id,
        "response_type": "code",
        "scope": scope,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    if identity_provider_hint:
        q["kc_idp_hint"] = identity_provider_hint
    return f"{authorization_endpoint_url()}?{urlencode(q)}"


async def exchange_authorization_code(
    code: str,
    redirect_uri: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
    }
    close = client is None
    c = client or httpx.AsyncClient(timeout=30.0)
    try:
        r = await c.post(token_endpoint_url(), data=data)
        r.raise_for_status()
        return r.json()
    finally:
        if close:
            await c.aclose()


async def refresh_tokens(
    refresh_token: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
    }
    close = client is None
    c = client or httpx.AsyncClient(timeout=30.0)
    try:
        r = await c.post(token_endpoint_url(), data=data)
        r.raise_for_status()
        return r.json()
    finally:
        if close:
            await c.aclose()


async def introspect_access_token(
    access_token: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    data = {
        "token": access_token,
        "token_type_hint": "access_token",
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
    }
    close = client is None
    c = client or httpx.AsyncClient(timeout=30.0)
    try:
        r = await c.post(introspection_endpoint_url(), data=data)
        r.raise_for_status()
        return r.json()
    finally:
        if close:
            await c.aclose()
