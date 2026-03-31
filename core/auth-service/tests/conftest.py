from __future__ import annotations

import uuid

import pytest

from api.core import config as api_config
from api.infrastructure.security import keycloak_jwt as kc_jwt


@pytest.fixture(autouse=True)
def _clear_keycloak_validator_cache() -> None:
    kc_jwt._validator_singleton.cache_clear()
    yield
    kc_jwt._validator_singleton.cache_clear()


@pytest.fixture
def event_sink() -> list:
    return []


@pytest.fixture
def app(event_sink, monkeypatch):
    monkeypatch.setattr(api_config.settings, "keycloak_issuer", "http://keycloak.test/realms/demo")
    monkeypatch.setattr(api_config.settings, "keycloak_jwks_url", "http://keycloak.test/jwks")
    monkeypatch.setattr(api_config.settings, "keycloak_client_id", "test-client")
    monkeypatch.setattr(api_config.settings, "keycloak_client_secret", "test-secret")
    monkeypatch.setattr(
        api_config.settings,
        "auth_oidc_redirect_uri",
        "http://client.test/oauth/callback",
    )
    monkeypatch.setattr(api_config.settings, "database_url", "postgresql+asyncpg://x:x@localhost:1/x")
    monkeypatch.setattr(api_config.settings, "kafka_bootstrap_servers", None)
    monkeypatch.setattr(api_config.settings, "oidc_require_mfa", False)
    monkeypatch.setattr(api_config.settings, "auth_token_validation_mode", "jwt")

    from auth_service.app import create_app

    return create_app(test_event_sink=event_sink, enable_db_middleware=False)


@pytest.fixture
async def http_client(app):
    import httpx
    from asgi_lifespan import LifespanManager

    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client


@pytest.fixture
def tenant_uuid() -> uuid.UUID:
    return uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
