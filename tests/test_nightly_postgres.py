"""Native PostgreSQL locks and commit visibility; reuse the owned CI DB fixture."""
import asyncio
from pathlib import Path
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from auth_service.nightly_store import PostgresNightlyStore
from auth_service.nightly_state import Refused
from test_nightly_state import REGISTER, cmd

@pytest.fixture
async def registry(siwe_postgres_url):
    engine=create_async_engine(siwe_postgres_url)
    async with engine.begin() as db:
        await db.execute(text(Path(__file__).with_name('fixtures').joinpath('nightly/0006_nightly_run.sql').read_text()))
        await db.execute(text('TRUNCATE auth_nightly_run'))
        assert (await db.execute(text("SELECT relpersistence::text FROM pg_class WHERE oid=to_regclass('auth_nightly_run')"))).scalar_one()=='p'
    try:yield engine,PostgresNightlyStore(engine)
    finally:await engine.dispose()

@pytest.mark.asyncio
async def test_real_commit_lock_seal_completion_and_reopened_adapter(registry):
    engine,store=registry
    await store.command(REGISTER);bound=await store.command(cmd('admit'))
    # The actual native commit guard owns the same row lock as sealing.
    async with engine.begin() as db:
        await store.assert_pending(db,bound)
        sealing=asyncio.create_task(store.command(cmd('seal')))
        await asyncio.sleep(.05)
        assert not sealing.done()
    assert (await sealing)['phase']=='sealed'
    with pytest.raises(Refused):await PostgresNightlyStore(engine).command(cmd('retire'))
    await store.command(cmd('complete',operation=bound['operation']))
    assert (await PostgresNightlyStore(engine).command(cmd('retire')))['terminal_verified']
    async with engine.begin() as db:
        with pytest.raises(Refused):await store.assert_pending(db,bound)
    with pytest.raises(Refused):await store.command(cmd('verify'))

@pytest.mark.asyncio
async def test_native_transaction_rollback_and_unrelated_owner_isolation(registry):
    engine,store=registry
    await store.command(REGISTER);await store.command(REGISTER|{'owner':'portal'})
    bound=await store.command(cmd('admit'))
    with pytest.raises(RuntimeError):
        async with engine.begin() as db:
            await store.assert_pending(db,bound)
            await db.execute(text("UPDATE auth_nightly_run SET state=jsonb_set(state,'{operations}', '{}'::jsonb) WHERE owner='auth'"))
            raise RuntimeError('rollback')
    await store.command(cmd('seal'))
    with pytest.raises(Refused):await store.command(cmd('retire'))
    assert (await store.command(cmd('verify',owner='portal')))['active']
    with pytest.raises(Refused):await store.command(cmd('complete',operation=bound['operation'],generation='d'*64))
    await store.command(cmd('complete',operation=bound['operation']))
    assert (await store.command(cmd('retire')))['terminal_verified']
