"""Real Redis replica/restart, replay, replacement, expiry and outage checks."""

import asyncio
from dataclasses import asdict
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
from auth_service import wallet_bind
from auth_service.schemas import AuthMeResponse
from auth_service.siwe import SiweError
from auth_service.siwe_nonces import SiweNonceStore, SiweStoreUnavailable, nonce_runtime
from eth_account import Account
from fastapi import FastAPI
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

PERSON = AuthMeResponse(sub="shared-siwe-person")
ADDRESS = Account.from_key(bytes.fromhex("33" * 32)).address


@pytest.mark.asyncio
async def test_other_replica_consumes_once_and_does_not_expose_subject_keys(
    nonce_store, siwe_redis_url
):
    challenge = await wallet_bind.issue_siwe_nonce(
        PERSON, address=ADDRESS, store=nonce_store
    )
    key = nonce_store.key(PERSON.sub)
    assert PERSON.sub not in key
    assert 0 < await nonce_store.redis.ttl(key) <= 600
    async with Redis.from_url(siwe_redis_url) as client:
        second = SiweNonceStore(client)
        outcomes = await asyncio.gather(
            nonce_store.consume(PERSON.sub),
            second.consume(PERSON.sub),
            return_exceptions=True,
        )
    assert sum(isinstance(value, dict) for value in outcomes) == 1
    assert sum(isinstance(value, SiweError) for value in outcomes) == 1
    assert asdict(challenge) in outcomes


@pytest.mark.asyncio
async def test_new_challenge_replaces_prior_and_other_subject_cannot_consume(
    nonce_store,
):
    old = await wallet_bind.issue_siwe_nonce(PERSON, address=ADDRESS, store=nonce_store)
    current = await wallet_bind.issue_siwe_nonce(
        PERSON, address=ADDRESS, store=nonce_store
    )
    with pytest.raises(SiweError):
        await nonce_store.consume("another-person")
    assert current.nonce != old.nonce
    assert (await nonce_store.consume(PERSON.sub))["message"] == current.message


@pytest.mark.asyncio
async def test_expired_challenge_is_unusable(nonce_store):
    await wallet_bind.issue_siwe_nonce(PERSON, address=ADDRESS, store=nonce_store)
    await nonce_store.redis.expire(nonce_store.key(PERSON.sub), 0)
    with pytest.raises(SiweError, match="expired"):
        await nonce_store.consume(PERSON.sub)


@pytest.mark.asyncio
async def test_corrupt_storage_fails_closed(nonce_store):
    await nonce_store.redis.set(nonce_store.key(PERSON.sub), "not-json")
    with pytest.raises(SiweStoreUnavailable):
        await nonce_store.consume(PERSON.sub)
    with pytest.raises(SiweError):
        await nonce_store.consume(PERSON.sub)


@pytest.mark.asyncio
async def test_outage_never_creates_or_consumes_local_fallback():
    redis = AsyncMock()
    redis.set.side_effect = RedisConnectionError("private dependency detail")
    redis.getdel.side_effect = RedisConnectionError("private dependency detail")
    store = SiweNonceStore(redis)
    with pytest.raises(SiweStoreUnavailable):
        await wallet_bind.issue_siwe_nonce(PERSON, address=ADDRESS, store=store)
    with pytest.raises(SiweStoreUnavailable):
        await store.consume(PERSON.sub)


@pytest.mark.asyncio
async def test_missing_storage_does_not_prevent_oidc_startup(monkeypatch, app):
    monkeypatch.delenv("AUTH_SIWE_REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    async with nonce_runtime() as store:
        assert store is None
    from asgi_lifespan import LifespanManager
    from auth_service.deps import get_current_auth_user

    app.dependency_overrides[get_current_auth_user] = lambda: PERSON
    async with (
        LifespanManager(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://auth.test"
        ) as client,
    ):
        login = await client.post("/auth/login", json={})
        assert login.status_code == 200, login.text
        assert login.json()["authorization_url"]
        challenge = await client.post("/auth/siwe/nonce", json={"address": ADDRESS})
        assert challenge.status_code == 503


@pytest.mark.asyncio
async def test_http_storage_outage_returns_503_without_dependency_details(monkeypatch):
    from auth_service import routes
    from auth_service.deps import get_current_auth_user

    app = FastAPI()
    app.include_router(routes.router, prefix="/auth")
    app.dependency_overrides[get_current_auth_user] = lambda: PERSON
    redis = AsyncMock()
    redis.set.side_effect = RedisConnectionError("private dependency detail")
    app.state.siwe_nonce_store = SiweNonceStore(redis)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://auth.test"
    ) as client:
        response = await client.post("/auth/siwe/nonce", json={"address": ADDRESS})
    assert response.status_code == 503, response.text
    assert "private dependency detail" not in response.text


@pytest.mark.asyncio
async def test_http_challenge_can_bind_on_another_replica(
    nonce_store, siwe_redis_url, base_wallet_verifier, monkeypatch
):
    from auth_service import routes
    from auth_service.deps import get_current_auth_user
    from eth_account.messages import encode_defunct

    app = FastAPI()
    app.include_router(routes.router, prefix="/auth")
    app.dependency_overrides[get_current_auth_user] = lambda: PERSON
    app.dependency_overrides[routes.get_db_session] = lambda: AsyncMock()
    app.state.siwe_nonce_store = nonce_store
    persisted = wallet_bind.WalletBinding(PERSON.sub, None, ADDRESS, datetime.now(UTC))
    save = AsyncMock(return_value=persisted)
    monkeypatch.setattr(wallet_bind, "upsert_wallet_binding", save)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://auth.test"
    ) as client:
        response = await client.post("/auth/siwe/nonce", json={"address": ADDRESS})
        assert response.status_code == 200, response.text
        message = response.json()["message"]
        signature = (
            Account.from_key(bytes.fromhex("33" * 32))
            .sign_message(encode_defunct(text=message))
            .signature.hex()
        )
        async with Redis.from_url(siwe_redis_url) as second:
            app.state.siwe_nonce_store = SiweNonceStore(second)
            accepted = await client.post(
                "/auth/siwe/bind", json={"message": message, "signature": signature}
            )
            assert accepted.status_code == 200, accepted.text
            replay = await client.post(
                "/auth/siwe/bind", json={"message": message, "signature": signature}
            )
            assert replay.status_code == 400
    save.assert_awaited_once()


@pytest.mark.asyncio
async def test_runtime_closes_redis_when_service_fails(monkeypatch):
    from auth_service import siwe_nonces

    redis = AsyncMock()
    redis.__aenter__.return_value = redis
    monkeypatch.setenv("AUTH_SIWE_REDIS_URL", "redis://nonce.test:6379/0")
    monkeypatch.setattr(siwe_nonces.Redis, "from_url", lambda *a, **kw: redis)
    with pytest.raises(RuntimeError):
        async with nonce_runtime():
            raise RuntimeError("service failed")
    redis.__aexit__.assert_awaited_once()
