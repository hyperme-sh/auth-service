"""Real PostgreSQL replica/restart, replay, replacement, expiry and outage checks."""

import asyncio
from dataclasses import asdict
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
from auth_service import wallet_bind
from auth_service.schemas import AuthMeResponse
from auth_service.siwe import SiweError
from auth_service.siwe_nonces import SiweStoreUnavailable, nonce_runtime
from eth_account import Account
from fastapi import FastAPI
from sqlalchemy import text
from auth_service.siwe_postgres import PostgresChallengeStore
from sqlalchemy.exc import OperationalError

PERSON = AuthMeResponse(sub="shared-siwe-person")
ADDRESS = Account.from_key(bytes.fromhex("33" * 32)).address


@pytest.mark.asyncio
async def test_other_replica_consumes_once_and_does_not_expose_subject_keys(
    nonce_store, siwe_postgres_url
):
    challenge = await wallet_bind.issue_siwe_nonce(
        PERSON, address=ADDRESS, store=nonce_store
    )
    key = nonce_store.key(PERSON.sub)
    assert PERSON.sub not in key
    second = PostgresChallengeStore(nonce_store.engine)
    outcomes = await asyncio.gather(nonce_store.consume(PERSON.sub), second.consume(PERSON.sub), return_exceptions=True)
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
    await nonce_store.expire(PERSON.sub)
    with pytest.raises(SiweError, match="expired"):
        await nonce_store.consume(PERSON.sub)


@pytest.mark.asyncio
async def test_corrupt_storage_fails_closed(nonce_store):
    async with nonce_store.engine.begin() as db:
        await db.execute(text("INSERT INTO auth_siwe_challenges VALUES(:subject, '[]'::jsonb, clock_timestamp()+interval '1 minute',NULL,0)"), {'subject':nonce_store.key(PERSON.sub)})
    with pytest.raises(SiweStoreUnavailable):
        await nonce_store.consume(PERSON.sub)
    with pytest.raises(SiweError):
        await nonce_store.consume(PERSON.sub)


@pytest.mark.asyncio
async def test_outage_never_creates_or_consumes_local_fallback():
    store = AsyncMock()
    store.put.side_effect = SiweStoreUnavailable('unavailable')
    store.consume.side_effect = SiweStoreUnavailable('unavailable')
    with pytest.raises(SiweStoreUnavailable):
        await wallet_bind.issue_siwe_nonce(PERSON, address=ADDRESS, store=store)
    with pytest.raises(SiweStoreUnavailable):
        await store.consume(PERSON.sub)


@pytest.mark.asyncio
async def test_missing_storage_does_not_prevent_oidc_startup(monkeypatch, app):
    for name in ('AUTH_SIWE_DATABASE_URL','DATABASE_URL','DATABASE_URL_FILE'):
        monkeypatch.delenv(name, raising=False)
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
    app.state.siwe_nonce_store = AsyncMock()
    app.state.siwe_nonce_store.put.side_effect = SiweStoreUnavailable('private dependency detail')
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://auth.test"
    ) as client:
        response = await client.post("/auth/siwe/nonce", json={"address": ADDRESS})
    assert response.status_code == 503, response.text
    assert "private dependency detail" not in response.text


@pytest.mark.asyncio
async def test_http_challenge_can_bind_on_another_replica(
    nonce_store, siwe_postgres_url, base_wallet_verifier, monkeypatch
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
        app.state.siwe_nonce_store = PostgresChallengeStore(nonce_store.engine)
        accepted = await client.post('/auth/siwe/bind', json={'message':message,'signature':signature})
        assert accepted.status_code == 200, accepted.text
        replay = await client.post('/auth/siwe/bind', json={'message':message,'signature':signature})
        assert replay.status_code == 400
    save.assert_awaited_once()
