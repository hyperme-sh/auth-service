"""Proof broker HTTP and native sealing contracts; CI only."""
import asyncio
import copy
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
import httpx
import pytest
from fastapi import FastAPI
from cryptography.fernet import Fernet
from auth_service.linked_oidc_routes import router
from auth_service import linked_oidc_runtime as runtime
from auth_service import linked_oidc_state as state

class Value:
    def __init__(self,value):self.value=value
    def scalar_one(self):return self.value

class Engine:
    def __init__(self):self.rows={};self.lock=asyncio.Lock();self.now=100
    @asynccontextmanager
    async def begin(self):
        async with self.lock:
            staged=copy.deepcopy(self.rows);owner=self
            class DB:
                async def execute(self,query,params=None):
                    nonlocal staged
                    q=str(query)
                    if q.startswith('SELECT state'):return Value(staged)
                    if q.startswith('UPDATE'):staged=json.loads(params['state'])
                    return Value(None)
                async def scalar(self,query):return owner.now
            yield DB()
            self.rows=staged

@pytest.fixture
def setup(monkeypatch):
    config={'version':1,'serviceToken':'s'*43,'sealingKey':Fernet.generate_key().decode(),
        'provider':dict(origin='https://test.s3r.ch',issuer='https://issuer.example',tenant='tenant',tenantClaim='tid',
        clientId='s3rch',clientSecret='secret',authorizationEndpoint='https://issuer.example/auth',
        tokenEndpoint='https://issuer.example/token',redirectUri='https://test.s3r.ch/callback',jwks={'keys':[]})}
    original=dict(token='signed',id='i'*64,issuedAt=100,expiresAt=160,origin='https://test.s3r.ch',
        credential=dict(kind='oidc',iss='https://issuer.example',tenant='tenant',sub='person'))
    monkeypatch.setattr(runtime,'configuration',lambda:copy.deepcopy(config))
    calls=[]
    async def exchange(provider,row,code,verifier):
        calls.append((code,verifier))
        return 'private-id-token',dict(iss='https://issuer.example',sub='person',tid='tenant',aud='s3rch',nonce='i'*64,iat=100,auth_time=100,exp=160)
    monkeypatch.setattr(runtime,'exchange',exchange)
    app=FastAPI();app.include_router(router);app.state.async_engine=Engine();app.state.linked_oidc_slots=asyncio.Semaphore(4)
    return app,config,original,calls

@pytest.mark.asyncio
async def test_start_exchange_exact_readback_replay_cancel_and_scope(setup):
    app,config,original,calls=setup
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit',headers={'Authorization':'Bearer '+config['serviceToken']}) as client:
        async def post(action,**kw):return await client.post('/auth/linked-oidc/v1/'+action,json={'challenge':original,**kw})
        first=await post('start');assert first.status_code==200
        assert first.headers['cache-control']=='private, no-store'
        assert (await post('start')).json()==first.json()
        row=next(iter(app.state.async_engine.rows.values()))
        args={'state':row['state'],'code':'one-time-code'}
        assert (await post('exchange',state='wrong',code='code')).status_code==409
        assert not calls
        result=await post('exchange',**args);assert result.json()['idToken']=='private-id-token'
        assert (await post('result')).json()==result.json()
        assert (await post('exchange',**args)).status_code==409 and len(calls)==1
        assert 'private-id-token' not in json.dumps(app.state.async_engine.rows)
        assert (await post('cancel')).status_code==200
        assert (await post('cancel')).status_code==200
        assert (await post('result')).status_code==409
        assert (await client.post('/auth/linked-oidc/v1/start',json={'challenge':original},headers={'Authorization':'Bearer foreign'})).status_code==409

@pytest.mark.asyncio
async def test_cancellation_wins_against_inflight_provider(setup,monkeypatch):
    app,config,original,calls=setup
    entered,release=asyncio.Event(),asyncio.Event()
    original_exchange=runtime.exchange
    async def delayed(*args):
        entered.set();await release.wait();return await original_exchange(*args)
    monkeypatch.setattr(runtime,'exchange',delayed)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit',headers={'Authorization':'Bearer '+config['serviceToken']}) as client:
        await client.post('/auth/linked-oidc/v1/start',json={'challenge':original})
        row=next(iter(app.state.async_engine.rows.values()))
        task=asyncio.create_task(client.post('/auth/linked-oidc/v1/exchange',json={'challenge':original,'state':row['state'],'code':'code'}))
        await asyncio.wait_for(entered.wait(),2)
        assert (await client.post('/auth/linked-oidc/v1/cancel',json={'challenge':original})).status_code==200
        release.set();assert (await task).status_code==409
        assert next(iter(app.state.async_engine.rows.values()))['sealedProof'] is None
