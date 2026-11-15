"""Shared store contract, executed only by Infra's scheduled auth-consumers lane."""
import asyncio
from contextlib import asynccontextmanager
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from auth_service.siwe import SiweError
from auth_service.siwe_postgres import PostgresChallengeStore


@pytest.fixture
async def fixture():
    path = Path(os.environ['SIWE_FIXTURE_SCRIPT'])
    spec = importlib.util.spec_from_file_location('siwe_fixture', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.environment(os.environ)
    subprocess.run([sys.executable, str(path), 'reset-case'], check=True, timeout=60)
    return module


@asynccontextmanager
async def connect(backend, *, fault=False):
    config = json.loads((Path(os.environ['SIWE_FIXTURE_DIR'])/'stores.json').read_text())
    url = make_url(config['postgres']).set(drivername='postgresql+asyncpg')
    if fault: url = url.set(password='deliberately-wrong-fixture-password')
    engine = create_async_engine(url)
    try: yield PostgresChallengeStore(engine)
    finally: await engine.dispose()


@pytest.fixture(params=['postgres'])
async def store(request, fixture):
    async with connect(request.param) as value:
        yield request.param, value


async def test_replace_and_subject_isolation(store):
    _, value = store
    await value.put('siwe-person', {'nonce':'old'})
    await value.put('siwe-person', {'nonce':'new'})
    with pytest.raises(SiweError): await value.consume('other-person')
    assert await value.consume('siwe-person') == {'nonce':'new'}
    with pytest.raises(SiweError): await value.consume('siwe-person')


async def test_concurrent_consume_has_one_winner(store):
    backend, value = store
    await value.put('siwe-person', {'nonce':'one'})
    async with connect(backend) as second:
        outcomes = await asyncio.gather(*[s.consume('siwe-person') for s in [value, second]*4], return_exceptions=True)
    assert sum(isinstance(x, dict) for x in outcomes) == 1
    assert sum(isinstance(x, SiweError) for x in outcomes) == 7


async def test_ten_minute_expiry(store, fixture):
    _, value = store
    await value.put('siwe-person', {'nonce':'one'})
    await fixture.force_expired(value)
    with pytest.raises(SiweError): await value.consume('siwe-person')
    with pytest.raises(SiweError): await value.consume('siwe-person')


async def test_explicit_expire(store):
    _, value = store
    await value.put('siwe-person', {'nonce':'one'})
    await value.expire('siwe-person')
    with pytest.raises(SiweError): await value.consume('siwe-person')


async def test_client_restart_preserves_unexpired_value(store):
    backend, _ = store
    async with connect(backend) as writer: await writer.put('siwe-person', {'nonce':'one'})
    async with connect(backend) as reader: assert await reader.consume('siwe-person') == {'nonce':'one'}


async def test_signature_then_checksum_write_and_no_replay(store, fixture, monkeypatch):
    backend, value = store
    app, save, address = fixture.configure_http(monkeypatch, value)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://auth.test') as client:
        response = await client.post('/auth/siwe/nonce', json={'address':address.lower()})
        assert response.status_code == 200, response.text
        message = response.json()['message']
        bad = Account.from_key(bytes.fromhex('44'*32)).sign_message(encode_defunct(text=message)).signature.hex()
        refused = await client.post('/auth/siwe/bind', json={'message':message, 'signature':bad})
        assert refused.status_code == 400, refused.text
        save.assert_not_awaited()
        good = Account.from_key(bytes.fromhex('33'*32)).sign_message(encode_defunct(text=message)).signature.hex()
        async with connect(backend) as second:
            app.state.siwe_nonce_store = second
            accepted = await client.post('/auth/siwe/bind', json={'message':message, 'signature':good})
            assert accepted.status_code == 200, accepted.text
            assert (await client.post('/auth/siwe/bind', json={'message':message, 'signature':good})).status_code == 400
    save.assert_awaited_once()
    assert save.call_args.kwargs['wallet_address'] == address


async def test_store_failure_returns_503_without_binding(store, fixture, monkeypatch):
    backend, value = store
    app, save, address = fixture.configure_http(monkeypatch, value)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://auth.test') as client:
        response = await client.post('/auth/siwe/nonce', json={'address':address})
        assert response.status_code == 200
        message = response.json()['message']
        signature = Account.from_key(bytes.fromhex('33'*32)).sign_message(encode_defunct(text=message)).signature.hex()
        async with connect(backend, fault=True) as failed:
            app.state.siwe_nonce_store = failed
            for path, body in [('/nonce', {'address':address}), ('/bind', {'message':message, 'signature':signature})]:
                result = await client.post('/auth/siwe'+path, json=body)
                assert result.status_code == 503, result.text
                assert 'fixture-password' not in result.text
    save.assert_not_awaited()


async def test_postgres_store_load(store):
    """Bounded scheduled storage capacity check, without external RPC latency."""
    import time
    _, value = store
    gate=asyncio.Semaphore(50)
    samples=[]
    async def pair(index):
        async with gate:
            started=time.perf_counter()
            subject=f'load-{index}'
            await value.put(subject,{'nonce':f'load-nonce-{index}'})
            assert await value.peek(subject)=={'nonce':f'load-nonce-{index}'}
            await value.consume_verified(subject,f'load-nonce-{index}')
            samples.append(time.perf_counter()-started)
    started=time.perf_counter()
    await asyncio.gather(*(pair(i) for i in range(2000)))
    elapsed=time.perf_counter()-started
    p95=sorted(samples)[int(len(samples)*0.95)-1]
    result={'pairs':len(samples),'workers':50,'pairs_per_second':len(samples)/elapsed,'p95_ms':p95*1000}
    print(json.dumps(result,sort_keys=True))
    assert p95<=0.1 and len(samples)/elapsed>=100, result
