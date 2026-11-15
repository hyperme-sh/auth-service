"""PostgreSQL adapter units using a transactional SQL double, no server."""
import asyncio
import copy
import json
from contextlib import asynccontextmanager
import pytest
from auth_service.pairing_store import PostgresPairingStore, PairingUnavailable
from auth_service.pairing_state import empty
from auth_service.pairing_wire import capability, b64
from test_pairing_state import SCOPE, REQUEST, SESSION, RECEIVER


class Value:
    def __init__(self,value):self.value=value
    def scalar_one(self):return self.value


class Engine:
    def __init__(self):self.state=None;self.lock=asyncio.Lock();self.queries=[];self.fail=False
    @asynccontextmanager
    async def begin(self):
        async with self.lock:
            staged=copy.deepcopy(self.state)
            parent=self
            class DB:
                async def execute(self,query,params=None):
                    nonlocal staged
                    query=str(query);parent.queries.append(query)
                    if parent.fail:raise OSError()
                    if query.startswith('INSERT') and staged is None:staged=json.loads(params['state'])
                    if query.startswith('SELECT state'):return Value(staged)
                    if query.startswith('UPDATE'):staged=json.loads(params['state'])
                    return Value(None)
                async def scalar(self,query):return 100000
            yield DB()
            self.state=staged


def operation(cap=RECEIVER):return dict(action='create',session=SESSION,role='receiver',cap_hash=capability(cap),subject=None,
    payload={'request':REQUEST,'joinHash':b64(b'j'*32)},join_hash=None)


@pytest.mark.asyncio
async def test_shared_atomic_row_survives_adapter_restart_and_competing_create():
    engine=Engine();a=PostgresPairingStore(engine);b=PostgresPairingStore(engine)
    results=await asyncio.gather(a.execute(SCOPE,**operation()),b.execute(SCOPE,**operation(b64(b'x'*32))))
    assert sorted(r[0] for r in results)==[200,409]
    assert (await PostgresPairingStore(engine).execute(SCOPE,**operation()))[0]==200
    assert any('FOR UPDATE' in q for q in engine.queries)
    assert engine.state['operations']==3
    engine.fail=True
    with pytest.raises(PairingUnavailable):await a.execute(SCOPE,**operation())
    assert engine.state['operations']==3


@pytest.mark.asyncio
async def test_refused_capability_attempts_are_committed_not_rolled_back():
    engine=Engine();store=PostgresPairingStore(engine)
    await store.execute(SCOPE,**operation())
    op={**operation(b64(b'x'*32)),'action':'receive','payload':{}}
    assert (await store.execute(SCOPE,**op))[0]==403
    assert engine.state['sessions'][SESSION]['attempts']==1
