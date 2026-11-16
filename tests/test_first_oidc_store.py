"""PostgreSQL atomic first binding and cancellation contracts, CI only."""
import asyncio
import importlib.util
from pathlib import Path
import time
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from auth_service import first_oidc_link as core
from auth_service.first_oidc_store import FirstOidcStore

spec=importlib.util.spec_from_file_location('first_oidc_fixture',Path(__file__).with_name('test_first_oidc_link.py'))
fixture_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture_module)

@pytest.mark.asyncio
async def test_atomic_exact_retry_restart_cancel_and_config_rollback(siwe_postgres_url,monkeypatch):
    engine=create_async_engine(siwe_postgres_url)
    r,b,j,k,signer,token,claims=fixture_module.fixture(int(time.time()))
    proof=token();store=FirstOidcStore(engine);calls=0;original=core.issue
    def counted(*args,**kwargs):
        nonlocal calls
        calls+=1;return original(*args,**kwargs)
    monkeypatch.setattr(core,'issue',counted)
    async def issue(current=lambda:None):return await FirstOidcStore(engine).issue(r,proof,b,j,k,signer,current)
    try:
        from importlib.resources import files
        async with engine.begin() as db:
            for statement in files('auth_service').joinpath('migrations/0008_first_oidc_link.sql').read_text().split(';'):
                if statement.strip():await db.execute(text(statement))
            await db.execute(text('TRUNCATE auth_first_oidc_link,auth_first_oidc_cancel'))
        count=0
        def changed():
            nonlocal count
            count+=1
            if count>1:raise core.FirstLinkRefused()
        with pytest.raises(core.FirstLinkRefused):await issue(changed)
        async with engine.connect() as db:assert await db.scalar(text('SELECT count(*) FROM auth_first_oidc_link'))==0
        calls=0
        first,second=await asyncio.gather(issue(),issue());assert first==second and calls==1
        assert await issue()==first and calls==1
        assert await store.cancel(r,b,lambda:None)=='already-issued'
        with pytest.raises(core.FirstLinkRefused):await store.issue(r,token(claims|{'exp':claims['exp']+1}),b,j,k,signer,lambda:None)
        async with engine.begin() as db:await db.execute(text('TRUNCATE auth_first_oidc_link,auth_first_oidc_cancel'))
        assert await store.cancel(r,b,lambda:None)=='cancelled'
        assert await store.cancel(r,b,lambda:None)=='cancelled'
        with pytest.raises(core.FirstLinkRefused):await issue()
        async with engine.connect() as db:assert await db.scalar(text('SELECT count(*) FROM auth_first_oidc_link'))==0
    finally:await engine.dispose()
