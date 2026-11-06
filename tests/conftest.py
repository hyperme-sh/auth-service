from __future__ import annotations

import uuid

import historical_db_fixture  # noqa: F401; verified test-only migration snapshot

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
    # Route/JWT unit tests isolate the external owner. Native enrollment tests
    # use the actual owner router and PostgreSQL instead of this fixture.
    from auth_service import identity_owner
    async def owner(operation, **payload):
        if operation not in {'seed-operator', 'seed-host', 'provision-operator'}:
            raise AssertionError('Unexpected identity-owner operation: ' + operation)
        return None
    monkeypatch.setattr(identity_owner, 'call', owner)
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
    monkeypatch.setattr(api_config.settings, "oidc_require_mfa", False)
    monkeypatch.setattr(api_config.settings, "auth_token_validation_mode", "jwt")
    monkeypatch.setattr(
        api_config.settings,
        "api_key_exchange_jwt_secret",
        "test-api-key-exchange-secret-min-32-chars!!",
    )

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


@pytest.fixture(autouse=True)
def _published_payloads_follow_wire_contracts(monkeypatch):
    """Validate actual application publications without enabling a live transport."""
    from api.infrastructure.messaging.tenant_event_publisher import NoOpTenantEventPublisher
    from controlplane_events.contracts import validate_event_envelope
    from controlplane_events.envelope import ControlPlaneEventEnvelope
    original = NoOpTenantEventPublisher.publish
    async def checked(self, **kwargs):
        validate_event_envelope(ControlPlaneEventEnvelope(service='contract-test', **kwargs))
        return await original(self, **kwargs)
    monkeypatch.setattr(NoOpTenantEventPublisher, 'publish', checked)


@pytest.fixture
async def base_wallet_verifier(monkeypatch):
    """Use the real shared verifier with deterministic Base RPC replies."""
    import json
    from contextlib import asynccontextmanager

    import httpx
    from auth_service import wallet_bind
    from controlplane_identity.wallet import BaseWalletVerifier

    monkeypatch.setenv("AUTH_SIWE_CHAIN_ID", "84532")

    def respond(request):
        method = json.loads(request.content)["method"]
        result = {
            "eth_chainId": "0x14a34",
            "eth_blockNumber": "0x123",
            "eth_getCode": "0x",
        }[method]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        verifier = BaseWalletVerifier(
            chain_id=84532, rpc_url="https://base.test", client=client
        )

        @asynccontextmanager
        async def factory():
            yield verifier

        monkeypatch.setattr(wallet_bind, "wallet_verifier", factory)
        yield verifier



@pytest.fixture(scope="session")
def siwe_redis_url():
    from testcontainers.redis import RedisContainer

    with RedisContainer("redis:7-alpine@sha256:8b81dd37ff027bec4e516d41acfbe9fe2460070dc6d4a4570a2ac5b9d59df065") as container:
        yield f"redis://{container.get_container_host_ip()}:{container.get_exposed_port(6379)}/0"


@pytest.fixture
async def nonce_store(siwe_redis_url):
    from redis.asyncio import Redis
    from auth_service.siwe_nonces import SiweNonceStore

    async with Redis.from_url(siwe_redis_url, socket_timeout=5) as redis:
        await redis.flushdb()
        yield SiweNonceStore(redis)
