"""Auth's owner transaction, attempt cap and expiry contracts."""
import asyncio
import uuid
import pytest
from sqlalchemy import text
from auth_service.siwe import SiweError
from auth_service.siwe_nonces import SiweStoreUnavailable


async def test_enqueue_has_one_winner_and_blocks_new_issue(nonce_store):
    store = nonce_store
    await store.put('person', {'nonce':'one'})
    results = await asyncio.gather(*[store.enqueue('person','one',{'subject':'person'}) for _ in range(8)],return_exceptions=True)
    assert sum(isinstance(x,uuid.UUID) for x in results)==1
    assert sum(isinstance(x,SiweError) for x in results)==7
    with pytest.raises(SiweStoreUnavailable):
        await store.put('person', {'nonce':'two'})


async def test_duplicate_nonce_and_failed_enqueue_rollback(nonce_store):
    store=nonce_store
    await store.put('person',{'nonce':'one'})
    with pytest.raises(SiweStoreUnavailable):
        await store.put('other',{'nonce':'one'})
    async with store.engine.begin() as db:
        await db.execute(text("INSERT INTO auth_wallet_commands VALUES(:id,:subject,'{}',clock_timestamp())"),{'id':uuid.uuid4(),'subject':store.key('person')})
    with pytest.raises(SiweStoreUnavailable):
        await store.enqueue('person','one',{})
    assert await store.peek('person')=={'nonce':'one'}


async def test_attempt_limit_and_replacement_isolation(nonce_store):
    store=nonce_store
    await store.put('person',{'nonce':'one'})
    for _ in range(4):
        await store.failed('person','one')
    assert await store.peek('person')=={'nonce':'one'}
    await store.failed('person','one')
    with pytest.raises(SiweError): await store.peek('person')
    await store.put('person',{'nonce':'two'})
    await store.failed('person','one')
    assert await store.peek('person')=={'nonce':'two'}


async def test_expiry_cleanup_and_empty_restart(nonce_store):
    store=nonce_store
    with pytest.raises(SiweError,match='request a new nonce'): await store.peek('person')
    await store.put('person',{'nonce':'one'})
    async with store.engine.begin() as db:
        await db.execute(text("UPDATE auth_siwe_challenges SET expires_at=clock_timestamp()-interval '1 second'"))
    with pytest.raises(SiweError): await store.peek('person')
    await store.cleanup()
    async with store.engine.connect() as db:
        assert await db.scalar(text('SELECT count(*) FROM auth_siwe_challenges'))==0
