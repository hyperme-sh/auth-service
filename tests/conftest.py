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

    from auth_service import outbox
    from controlplane_events.contracts import validate_event_envelope
    from controlplane_events.envelope import ControlPlaneEventEnvelope
    async def observed(*, token, tenant_id, event_type, payload):
        envelope = ControlPlaneEventEnvelope(service='auth-service', tenant_id=tenant_id, event_type=event_type, payload=payload)
        validate_event_envelope(envelope)
        event_sink.append({'tenant_id':tenant_id,'event_type':event_type,'payload':payload})
    monkeypatch.setattr(outbox, 'publish_auth_event', observed)
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
def siwe_postgres_url():
    from testcontainers.postgres import PostgresContainer
    with PostgresContainer("postgres:16-alpine@sha256:20edbde7749f822887a1a022ad526fde0a47d6b2be9a8364433605cf65099416", driver="psycopg") as container:
        yield container.get_connection_url().replace('+psycopg', '+asyncpg')


@pytest.fixture
async def nonce_store(siwe_postgres_url, monkeypatch):
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy import text
    from pathlib import Path
    from auth_service.siwe_postgres import PostgresChallengeStore
    from auth_service import wallet_commands, wallet_bind
    engine = create_async_engine(siwe_postgres_url)
    async with engine.begin() as db:
        for name in ('0002_siwe_challenges.sql', '0004_siwe_nonce_attempts.sql'):
            ddl = Path(__file__).parent.joinpath('fixtures/siwe', name).read_text()
            # Wheel tests carry the test fixture DDL below.
            ddl = '\n'.join(line for line in ddl.splitlines() if not line.lstrip().startswith('--'))
            for statement in ddl.split(';'):
                if statement.strip(): await db.execute(text(statement))
        await db.execute(text('TRUNCATE auth_siwe_challenges,auth_wallet_commands'))
    # Wallet verifier tests isolate the HTTP delivery boundary. Dedicated command
    # tests below exercise production delivery and uncertain response handling.
    async def deliver(engine, command_id):
        async with engine.begin() as db:
            payload = await db.scalar(text('SELECT payload FROM auth_wallet_commands WHERE id=:id'), {'id':command_id})
            result = await wallet_bind.upsert_wallet_binding(None, keycloak_sub=payload['subject'],
                email=payload['email'], wallet_address=payload['wallet_address'])
            await db.execute(text('DELETE FROM auth_wallet_commands WHERE id=:id'), {'id':command_id})
            return result
    monkeypatch.setattr(wallet_commands, 'deliver', deliver)
    try:
        yield PostgresChallengeStore(engine)
    finally:
        await engine.dispose()
