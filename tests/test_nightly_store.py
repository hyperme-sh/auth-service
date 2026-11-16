"""SQL adapter contracts use an explicitly substituted transactional database."""
import asyncio
import copy
import json
from contextlib import asynccontextmanager
import pytest
from auth_service.nightly_store import PostgresNightlyStore
from auth_service.nightly_state import Refused
from test_nightly_state import REGISTER, cmd


class Value:
    def __init__(self,value):self.value=value
    def scalar_one_or_none(self):return self.value


class Engine:
    def __init__(self):self.rows={};self.lock=asyncio.Lock();self.fail=False;self.queries=[]
    @asynccontextmanager
    async def begin(self):
        async with self.lock:
            rows=copy.deepcopy(self.rows);engine=self
            class DB:
                async def execute(self,query,params=None):
                    q=str(query);engine.queries.append(q)
                    if engine.fail:raise OSError()
                    if q.startswith('SET '):return Value(None)
                    if q.startswith('INSERT '):rows.setdefault((params['owner'],params['run']),json.loads(params['state']))
                    if q.startswith('SELECT '):
                        selected=[v for (owner,run),v in rows.items() if owner==params['owner'] and
                                  (v['grant_hash']==params['grant'] if 'grant' in params else run==params['run'])]
                        return Value(selected[0] if selected else None)
                    if q.startswith('UPDATE '):rows[(params['owner'],params['run'])]=json.loads(params['state'])
                    return Value(None)
            yield DB()
            self.rows=rows


@pytest.mark.asyncio
async def test_seal_races_admission_and_restart_never_misses_pending_work():
    engine=Engine();a=PostgresNightlyStore(engine);b=PostgresNightlyStore(engine)
    await a.command(REGISTER)
    results=await asyncio.gather(a.command(cmd('admit')),b.command(cmd('seal')),return_exceptions=True)
    if isinstance(results[0],dict):
        with pytest.raises(Refused):await b.command(cmd('retire'))
        await a.command(cmd('complete',operation=results[0]['operation']))
    assert (await PostgresNightlyStore(engine).command(cmd('retire')))['terminal_verified']
    assert any('FOR UPDATE' in q for q in engine.queries)


@pytest.mark.asyncio
async def test_foreign_owner_and_storage_failure_preserve_other_run():
    engine=Engine();store=PostgresNightlyStore(engine)
    await store.command(REGISTER)
    other=REGISTER|{'owner':'portal'};await store.command(other)
    await store.command(cmd('seal'));await store.command(cmd('retire'))
    assert (await store.command(cmd('verify',owner='portal')))['active']
    before=copy.deepcopy(engine.rows);engine.fail=True
    with pytest.raises(Refused):await store.command(cmd('seal',owner='portal'))
    assert engine.rows==before


@pytest.mark.asyncio
async def test_native_auth_mutation_requires_exact_pending_operation_under_lock():
    engine=Engine();store=PostgresNightlyStore(engine);await store.command(REGISTER)
    bound=await store.command(cmd('admit'));await store.command(cmd('seal'))
    async with engine.begin() as db:await store.assert_pending(db,bound)
    await store.command(cmd('complete',operation=bound['operation']))
    async with engine.begin() as db:
        with pytest.raises(Refused):await store.assert_pending(db,bound)
