"""CI PostgreSQL contracts for first enrollment and rolling old-writer guards."""
import asyncio
import importlib.util
from pathlib import Path
import time
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from auth_service.first_genesis_store import FirstGenesisStore
from auth_service import first_genesis as core
spec=importlib.util.spec_from_file_location('genesis_store_fixture',Path(__file__).with_name('test_first_genesis.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

@pytest.mark.asyncio
async def test_genesis_atomic_retry_and_old_oidc_writer_cannot_replace_owner(siwe_postgres_url,monkeypatch):
    engine=create_async_engine(siwe_postgres_url);store=FirstGenesisStore(engine)
    r,b,j,k,signer,token,claims=f.fixture(int(time.time()));proof=token()
    try:
        async with engine.begin() as db:
            for statement in Path(__file__).with_name('fixtures').joinpath('first-oidc/0008_first_oidc_link.sql').read_text().split(';'):
                if statement.strip():await db.execute(text(statement))
            for statement in Path(__file__).with_name('fixtures').joinpath('first-genesis/0009_first_genesis.sql').read_text().split('-- statement'):
                if statement.strip():await db.execute(text(statement))
            await db.execute(text('TRUNCATE auth_first_identity_binding,auth_first_oidc_link,auth_first_oidc_cancel,auth_first_genesis,auth_first_genesis_cancel'))
        count=0;original=core.issue
        def counted(*args):
            nonlocal count
            count+=1;return original(*args)
        monkeypatch.setattr(core,'issue',counted)
        async def issue(current=lambda:None):return await FirstGenesisStore(engine).issue(r,proof,b,j,k,signer,current)
        guard_calls=0
        def changed():
            nonlocal guard_calls
            guard_calls+=1
            if guard_calls>1:raise core.FirstLinkRefused()
        with pytest.raises(core.FirstLinkRefused):await issue(changed)
        async with engine.connect() as db:assert await db.scalar(text('SELECT count(*) FROM auth_first_identity_binding'))==0
        count=0
        a,z=await asyncio.gather(issue(),issue());assert a==z and count==1
        assert await issue()==a and count==1
        assert await store.cancel(r,b,lambda:None)=='already-issued'
        identity=core.fingerprint(dict(iss=b['issuer'],tenant=b['tenant'],sub=b['subject']))
        # A still-running older binary only knows the OIDC table. Its INSERT is fenced too.
        with pytest.raises(Exception):
            async with engine.begin() as db:
                await db.execute(text("INSERT INTO auth_first_oidc_link VALUES(:identity,'foreign','{}'::jsonb)"),{'identity':identity})
        async with engine.begin() as db:
            await db.execute(text("INSERT INTO auth_first_oidc_link VALUES(:identity,:principal,'{}'::jsonb)"),{'identity':identity,'principal':b['principal']})
        with pytest.raises(core.FirstLinkRefused):await store.issue(r,token(claims|{'exp':claims['exp']+1}),b,j,k,signer,lambda:None)
        async with engine.begin() as db:
            await db.execute(text('TRUNCATE auth_first_identity_binding,auth_first_oidc_link,auth_first_genesis,auth_first_genesis_cancel'))
            await db.execute(text("INSERT INTO auth_first_oidc_link VALUES(:identity,'foreign','{}'::jsonb)"),{'identity':identity})
        with pytest.raises(Exception):await issue()
        async with engine.begin() as db:await db.execute(text('TRUNCATE auth_first_identity_binding,auth_first_oidc_link,auth_first_genesis,auth_first_genesis_cancel'))
        assert await store.cancel(r,b,lambda:None)=='cancelled'
        with pytest.raises(core.FirstLinkRefused):await issue()
    finally:await engine.dispose()

@pytest.mark.asyncio
async def test_original_admission_drains_but_closed_or_retired_commit_rolls_back(siwe_postgres_url):
    from auth_service.nightly_runtime import admission
    from auth_service.nightly_store import PostgresNightlyStore
    from auth_service.nightly_state import Refused
    from test_nightly_state import REGISTER,cmd
    engine=create_async_engine(siwe_postgres_url);native=PostgresNightlyStore(engine)
    r,b,j,k,signer,token,_=f.fixture(int(time.time()))
    proof=token();store=FirstGenesisStore(engine)
    try:
        async with engine.begin() as db:
            for name in ('first-oidc/0008_first_oidc_link.sql','nightly/0006_nightly_run.sql','first-genesis/0009_first_genesis.sql'):
                for statement in Path(__file__).with_name('fixtures').joinpath(name).read_text().split('-- statement' if '0009' in name else ';'):
                    if statement.strip():await db.execute(text(statement))
            await db.execute(text('TRUNCATE auth_first_identity_binding,auth_first_oidc_link,auth_first_oidc_cancel,auth_first_genesis,auth_first_genesis_cancel,auth_nightly_run'))
        await native.command(REGISTER);bound=await native.command(cmd('admit'))
        context=admission.set(bound)
        try:
            count=0
            def close_at_commit():
                nonlocal count
                count+=1
                if count==2:bound['_closed']=True
            with pytest.raises(Refused):await store.issue(r,proof,b,j,k,signer,close_at_commit)
            async with engine.connect() as db:assert await db.scalar(text('SELECT count(*) FROM auth_first_genesis'))==0
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
