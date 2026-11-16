"""Real PostgreSQL proof consumption and rollback contracts, CI only."""
import asyncio
import time
from pathlib import Path
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from auth_service.linked_oidc_store import LinkedOidcStore
from auth_service import linked_oidc_state as state

@pytest.mark.asyncio
async def test_atomic_provider_claim_restart_and_rollback(siwe_postgres_url):
    engine=create_async_engine(siwe_postgres_url)
    provider=dict(origin='https://test.s3r.ch',issuer='https://issuer.example',tenant='tenant')
    now=int(time.time())
    original=dict(token='original',id='i'*64,issuedAt=now,expiresAt=now+60,origin=provider['origin'],
        credential=dict(kind='oidc',iss=provider['issuer'],tenant='tenant',sub='person'))
    store=LinkedOidcStore(engine)
    try:
        async with engine.begin() as db:
            await db.execute(text(Path(__file__).with_name('fixtures').joinpath('linked-oidc/0007_linked_oidc.sql').read_text()))
            await db.execute(text('TRUNCATE auth_linked_oidc'))
        def start(rows,key,at):rows[key]=state.begin(original,provider,now=at,state='s'*43,verifier='v'*43,run=None)
        await store.execute(provider,original,None,start)
        def consume(rows,key,at):return state.claim_exchange(rows[key],provider,original,state='s'*43,now=at,run=None)
        async def claim():
            try:return await LinkedOidcStore(engine).execute(provider,original,None,consume)
            except state.LinkedProofRefused:return 'refused'
        assert sorted(await asyncio.gather(claim(),claim()))==['refused','v'*43]
        def failed(rows,key,at):
            rows[key]['phase']='proved'
            raise RuntimeError('interrupted')
        with pytest.raises(RuntimeError):await store.execute(provider,original,None,failed)
        assert await LinkedOidcStore(engine).execute(provider,original,None,lambda rows,key,at:rows[key]['phase'])=='exchanging'
    finally:await engine.dispose()
