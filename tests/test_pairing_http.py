"""ASGI route contracts with substituted authorization and owner storage."""
import asyncio
import copy
from fastapi import FastAPI
import httpx
import pytest
from auth_service.pairing_routes import router
from auth_service.pairing_state import apply, empty
from auth_service.pairing_store import PairingUnavailable
from auth_service.pairing_wire import b64
from test_pairing_state import SCOPE, SESSION, REQUEST, RECEIVER, SENDER, admission
from auth_service.pairing_wire import capability


class Store:
    def __init__(self):self.state=empty();self.lock=asyncio.Lock();self.fail=False
    async def execute(self,scope,**operation):
        if self.fail:raise PairingUnavailable()
        async with self.lock:return apply(self.state,scope=scope,now=100000,**operation)


def make_app():
    app=FastAPI();app.include_router(router)
    app.state.pairing_store=Store();app.state.pairing_scopes=[SCOPE];app.state.pairing_slots=asyncio.Semaphore(8)
    return app


@pytest.mark.asyncio
async def test_unauthenticated_receiver_bootstrap_and_refusals(monkeypatch):
    app=make_app();headers={'Origin':SCOPE['destinationOrigin'],'X-Pairing-Role':'receiver','X-Pairing-Capability':RECEIVER}
    reserved=admission()
    await app.state.pairing_store.execute(SCOPE,action='admit',session=SESSION,role='sender',cap_hash=capability(SENDER),subject='subject',payload=reserved,join_hash=None)
    body={'scope':SCOPE,'payload':{'request':REQUEST,'joinHash':reserved['joinHash']}}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as c:
        path=f'/auth/sea-device-link/v1/sessions/{SESSION}/create'
        r=await c.post(path,json=body,headers=headers)
        assert r.status_code==200 and r.headers['cache-control']=='private, no-store'
        assert (await c.post(path,json=body,headers={**headers,'Origin':'https://wrong.example'})).status_code==403
        assert (await c.post(path,json={**body,'keyring':'private'},headers=headers)).status_code==400
        assert (await c.post(path,json=body,headers={**headers,'X-Pairing-Role':'sender','Origin':SCOPE['sourceOrigin']})).status_code==401
        assert (await c.post(path,content=b'x'*710001,headers={**headers,'Content-Type':'application/json'})).status_code==413
        app.state.pairing_store.fail=True
        assert (await c.post(path,json=body,headers=headers)).status_code==503
        app.state.pairing_store=None
        assert (await c.post(path,json=body,headers=headers)).status_code==503


@pytest.mark.asyncio
async def test_source_context_requires_tenant_permission_and_person(monkeypatch):
    app=make_app()
    claims={'sub':'person','iss':'https://issuer.example','tenant_id':SCOPE['tenant'],'scope':'auth:device:transfer'}
    async def auth(_):return claims
    monkeypatch.setattr('auth_service.pairing_routes.get_access_token_claims',auth)
    headers={'Origin':SCOPE['sourceOrigin'],'X-Pairing-Role':'sender','X-Pairing-Capability':RECEIVER,'Authorization':'Bearer synthetic'}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as c:
        path=f'/auth/sea-device-link/v1/sessions/{SESSION}/completed'
        assert (await c.post(path,json={'scope':SCOPE,'payload':{}},headers=headers)).status_code==404
        for patch in ({'tenant_id':'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'},{'scope':''},{'account_type':'service'},{'spanopticon_auth':'api_key'}):
            original=copy.deepcopy(claims);claims.update(patch)
            assert (await c.post(path,json={'scope':SCOPE,'payload':{}},headers=headers)).status_code==401
            claims.clear();claims.update(original)


@pytest.mark.asyncio
async def test_anonymous_requests_are_throttled_before_storage(monkeypatch):
    monkeypatch.setattr('auth_service.pairing_routes.monotonic',lambda: 100)
    app=make_app()
    headers={'Origin':SCOPE['destinationOrigin'],'X-Pairing-Role':'receiver','X-Pairing-Capability':RECEIVER}
    path=f'/auth/sea-device-link/v1/sessions/{SESSION}/receive'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as c:
        for _ in range(120):
            assert (await c.post(path,json={'scope':SCOPE,'payload':{}},headers=headers)).status_code==404
        assert (await c.post(path,json={'scope':SCOPE,'payload':{}},headers={**headers,'X-Forwarded-For':'other'})).status_code==429
        assert app.state.pairing_store.state['operations']==0
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('192.0.2.2',123)),base_url='http://unit') as c:
        assert (await c.post(path.replace('/receive','/create'),json={'scope':SCOPE,'payload':{'request':REQUEST,'joinHash':b64(b'j'*32)}},headers=headers)).status_code==404
        assert not app.state.pairing_store.state['sessions']


def test_anonymous_limiter_is_bounded_and_resets(monkeypatch):
    from auth_service.pairing_routes import AnonymousLimiter
    monkeypatch.setattr('auth_service.pairing_routes.monotonic',lambda: 100)
    limiter=AnonymousLimiter()
    for i in range(1024): assert limiter.allow(str(i))
    assert not limiter.allow('new')
    assert limiter.allow('0')
    monkeypatch.setattr('auth_service.pairing_routes.monotonic',lambda: 160)
    assert limiter.allow('new')
    assert len(limiter.clients)==1


@pytest.mark.asyncio
async def test_forged_sender_headers_cannot_bypass_pre_auth_allowance(monkeypatch):
    monkeypatch.setattr('auth_service.pairing_routes.monotonic',lambda: 100)
    calls=0
    async def refuse(_):
        nonlocal calls
        calls+=1
        raise ValueError()
    monkeypatch.setattr('auth_service.pairing_routes.get_access_token_claims',refuse)
    app=make_app()
    headers={'Origin':SCOPE['sourceOrigin'],'X-Pairing-Role':'sender',
             'X-Pairing-Capability':RECEIVER,'Authorization':'Bearer invalid'}
    path=f'/auth/sea-device-link/v1/sessions/{SESSION}/completed'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as c:
        for _ in range(120):
            assert (await c.post(path,json={'scope':SCOPE,'payload':{}},headers=headers)).status_code==401
        assert (await c.post(path,json={'scope':SCOPE,'payload':{}},headers=headers)).status_code==429
        assert calls==120
        # Refuse before body parsing as well as authentication.
        assert (await c.post(path,content=b'x'*710001,headers=headers)).status_code==429
    assert app.state.pairing_store.state['operations']==0


@pytest.mark.asyncio
async def test_admission_requires_source_auth_then_receiver_needs_no_bearer(monkeypatch):
    app=make_app()
    headers={'Origin':SCOPE['sourceOrigin'],'X-Pairing-Role':'sender','X-Pairing-Capability':SENDER}
    path=f'/auth/sea-device-link/v1/sessions/{SESSION}'
    async def auth(_):
        return {'sub':'person','iss':'https://issuer.example','tenant_id':SCOPE['tenant'],'scope':'auth:device:transfer'}
    monkeypatch.setattr('auth_service.pairing_routes.get_access_token_claims',auth)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as c:
        assert (await c.post(path+'/admit',json={'scope':SCOPE,'payload':admission()},headers=headers)).status_code==401
        assert not app.state.pairing_store.state['sessions']
        assert (await c.post(path+'/admit',json={'scope':SCOPE,'payload':admission()},headers={**headers,'Authorization':'Bearer synthetic'})).status_code==200
        rx={'Origin':SCOPE['destinationOrigin'],'X-Pairing-Role':'receiver','X-Pairing-Capability':RECEIVER}
        assert (await c.post(path+'/create',json={'scope':SCOPE,'payload':{'request':REQUEST,'joinHash':admission()['joinHash']}},headers=rx)).status_code==200
