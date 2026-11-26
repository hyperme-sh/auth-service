"""Auth's runtime connection contract, including the two-replica budget in CI."""
import asyncio
from contextlib import AsyncExitStack
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import httpx
import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from auth_service import deps, identity_owner, pairing_runtime, routes, transaction
from auth_service.app import create_app
from auth_service.database import runtime_engines
from auth_service.tenant_switch import TenantSwitchGrant
from controlplane_api.config import settings


async def test_explicit_separate_nonce_database_shares_the_total_budget(monkeypatch):
    monkeypatch.delenv("AUTH_DB_POOL_LIMIT", raising=False)
    owner = "postgresql://db.invalid/auth"
    nonce = "postgresql+asyncpg://db.invalid/nonces"
    engines = [Mock(dispose=AsyncMock()), Mock(dispose=AsyncMock())]
    with patch("auth_service.database.create_async_engine", side_effect=engines) as factory:
        async with runtime_engines(owner, nonce) as built:
            assert built == tuple(engines)
            assert factory.call_count == 2
            assert all(call.kwargs == {"pool_size": 1, "max_overflow": 0, "pool_pre_ping": True}
                       for call in factory.call_args_list)
    for engine in engines:
        engine.dispose.assert_awaited_once()


async def test_one_slot_can_bridge_a_legacy_replica_without_overflow(monkeypatch):
    monkeypatch.setenv("AUTH_DB_POOL_LIMIT", "1")
    owner = "postgresql://db.invalid/auth"
    engine = Mock(dispose=AsyncMock())
    with patch("auth_service.database.create_async_engine", return_value=engine) as factory:
        async with runtime_engines(owner, owner) as built:
            assert built == (engine, engine)
            assert factory.call_args.kwargs == {"pool_size": 1, "max_overflow": 0, "pool_pre_ping": True}
        with pytest.raises(ValueError):
            async with runtime_engines(owner, "postgresql://db.invalid/nonces"):
                pytest.fail("Split databases require two slots")
        monkeypatch.setenv("AUTH_DB_POOL_LIMIT", "3")
        with pytest.raises(ValueError):
            async with runtime_engines(owner, owner):
                pytest.fail("The configured limit cannot exceed two")


@pytest.fixture
def capped_auth_database(siwe_postgres_url):
    role = "auth_budget_" + uuid4().hex
    password = uuid4().hex
    url = make_url(siwe_postgres_url)
    admin = create_engine(url.set(drivername="postgresql+psycopg"))
    try:
        with admin.begin() as db:
            db.exec_driver_sql(f'CREATE ROLE "{role}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS CONNECTION LIMIT 4')
            db.exec_driver_sql(f'CREATE SCHEMA "{role}" AUTHORIZATION "{role}"')
            db.exec_driver_sql(f'ALTER ROLE "{role}" SET search_path TO "{role}"')
            db.exec_driver_sql(f'SET LOCAL ROLE "{role}"')
            db.exec_driver_sql(f'SET LOCAL search_path TO "{role}"')
            fixtures = Path(__file__).with_name("fixtures")
            for name in (
                "auth-budget/0001.sql", "siwe/0002_siwe_challenges.sql",
                "auth-budget/0003_token_issuance.sql", "siwe/0004_siwe_nonce_attempts.sql",
                "auth-budget/0005_sea_pairing.sql",
            ):
                db.exec_driver_sql((fixtures / name).read_text())
        yield url.set(username=role, password=password), admin
    finally:
        with admin.begin() as db:
            db.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{role}" CASCADE')
            db.exec_driver_sql(f'DROP ROLE IF EXISTS "{role}"')
        admin.dispose()


async def test_two_auth_replicas_share_their_four_connections(capped_auth_database, monkeypatch):
    url, admin = capped_auth_database
    tenant = str(uuid4())
    dsn = url.render_as_string(hide_password=False)
    monkeypatch.setattr(settings, "database_url", dsn)
    monkeypatch.setenv("DATABASE_URL", dsn)
    monkeypatch.setenv("AUTH_SIWE_CHAIN_ID", "84532")
    monkeypatch.delenv("USDC_CHAIN_ID", raising=False)
    monkeypatch.delenv("AUTH_SIWE_DATABASE_URL", raising=False)
    monkeypatch.delenv("AUTH_DB_POOL_LIMIT", raising=False)
    monkeypatch.delenv("STARTUP_IDENTITY_ENABLED", raising=False)
    monkeypatch.setattr(settings, "api_key_exchange_jwt_secret", "auth-budget-test-fixture-signing-key-" + uuid4().hex)
    monkeypatch.setattr(routes, "authorize_tenant_switch", AsyncMock(return_value=TenantSwitchGrant(role_name="user")))
    monkeypatch.setattr(identity_owner, "call", AsyncMock(return_value=None))
    monkeypatch.setattr(pairing_runtime, "read_scopes", lambda: ({"fixture": True},))
    monkeypatch.setattr(transaction, "is_tenancy_enabled", lambda: True)
    replicas = [create_app(), create_app()]
    work = []

    async with AsyncExitStack() as stack:
        for index, app in enumerate(replicas):
            subject = f"auth-budget-fixture-{index}"
            app.dependency_overrides[deps.get_access_token_claims] = lambda subject=subject: {
                "sub": subject, "email": f"{subject}@example.invalid",
            }
            await stack.enter_async_context(LifespanManager(app))
            assert app.state.siwe_nonce_store.engine is app.state.async_engine
            assert app.state.pairing_store.engine is app.state.async_engine
            assert app.state.async_engine.pool.size() == 2
            client = await stack.enter_async_context(httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://localhost"
            ))
            for _ in range(3):
                work.extend((
                    client.get("/api/v1/health/"),
                    client.post("/auth/switch-tenant", json={"tenant_id": tenant}),
                    client.post("/auth/siwe/nonce", json={"address": "0x" + "12" * 20, "chain_id": 84532}),
                ))

        async with asyncio.timeout(15):
            replies = await asyncio.gather(*work)
        assert all(reply.status_code == 200 for reply in replies), [(reply.url.path, reply.status_code) for reply in replies]
        assert all(reply.json().get("access_token") for reply in replies if reply.url.path == "/auth/switch-tenant")
        with admin.connect() as db:
            events = db.scalar(text(f'SELECT count(*) FROM "{url.username}".service_outbox WHERE tenant_id=:tenant'),
                               {"tenant": tenant})
        assert events >= 2
