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
        async with engine.begin() as db:
            for statement in Path(__file__).with_name('fixtures').joinpath('first-oidc/0008_first_oidc_link.sql').read_text().split(';'):
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

@pytest.mark.asyncio
async def test_original_admission_drains_but_closed_or_retired_commit_rolls_back(siwe_postgres_url):
    from auth_service.nightly_runtime import admission
    from auth_service.nightly_store import PostgresNightlyStore
    from auth_service.nightly_state import Refused
    from test_nightly_state import REGISTER,cmd
    engine=create_async_engine(siwe_postgres_url);native=PostgresNightlyStore(engine)
    r,b,j,k,signer,token,_=fixture_module.fixture(int(time.time()))
    proof=token();store=FirstOidcStore(engine)
    try:
        async with engine.begin() as db:
            for name in ('first-oidc/0008_first_oidc_link.sql','nightly/0006_nightly_run.sql'):
                for statement in Path(__file__).with_name('fixtures').joinpath(name).read_text().split(';'):
                    if statement.strip():await db.execute(text(statement))
            await db.execute(text('TRUNCATE auth_first_oidc_link,auth_first_oidc_cancel,auth_nightly_run'))
        await native.command(REGISTER);bound=await native.command(cmd('admit'))
        context=admission.set(bound)
        try:
            count=0
            def close_at_commit():
                nonlocal count
                count+=1
                if count==2:bound['_closed']=True
            with pytest.raises(Refused):await store.issue(r,proof,b,j,k,signer,close_at_commit)
            async with engine.connect() as db:assert await db.scalar(text('SELECT count(*) FROM auth_first_oidc_link'))==0
            bound.pop('_closed')
            await native.command(cmd('seal'))
            with pytest.raises(Refused):await native.command(cmd('admit'))
            with pytest.raises(Refused):await native.command(cmd('retire'))
            original=await store.issue(r,proof,b,j,k,signer,lambda:None)
            assert await store.issue(r,proof,b,j,k,signer,lambda:None)==original
            assert await store.cancel(r,b,lambda:None)=='already-issued'
            await native.command(cmd('complete',operation=bound['operation']))
            await native.command(cmd('retire'))
            with pytest.raises(Refused):await store.issue(r,proof,b,j,k,signer,lambda:None)
            with pytest.raises(Refused):await store.cancel(r,b,lambda:None)
        finally:admission.reset(context)
    finally:await engine.dispose()
