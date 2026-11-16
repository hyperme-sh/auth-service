"""ASGI and admission composition; database and cryptographic token issuer are substituted."""
import hashlib
import hmac
import json
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import httpx
import pytest
from auth_service.nightly_routes import router
from auth_service.nightly_middleware import NightlyMiddleware
from auth_service.nightly_runtime import admission, authenticate, verify_claims
from auth_service.nightly_store import PostgresNightlyStore
from auth_service import nightly_state as state
from test_nightly_state import REGISTER, SCOPE, cmd
from test_nightly_store import Engine


def setup():
    app=FastAPI();app.include_router(router);app.add_middleware(NightlyMiddleware)
    config=dict(version=1,ownerKeys={owner:f'{index+10:064x}' for index,owner in enumerate(sorted(state.OWNERS))},
                scopes={SCOPE['suite']:SCOPE})
    app.state.nightly_config=config;app.state.nightly_store=PostgresNightlyStore(Engine(),config['scopes'])
    calls=[]
    @app.get('/auth/me')
    async def native():
        calls.append(admission.get())
        if getattr(app.state,'native_error',False):return JSONResponse({'error':'synthetic'},status_code=503)
        return {'native':True}
    return app,config,calls


@pytest.mark.asyncio
async def test_authenticated_commands_and_native_completion_before_response():
    app,config,calls=setup()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        raw=json.dumps(REGISTER).encode();key=bytes.fromhex(config['ownerKeys']['auth'])
        headers={'Content-Type':'application/json','X-Nightly-Owner-Signature':hmac.new(key,raw,hashlib.sha256).hexdigest()}
        assert (await client.post('/auth/nightly-run/v1/command',content=raw,headers=headers)).status_code==200
        assert (await client.post('/auth/nightly-run/v1/command',content=raw+b' ',headers=headers)).status_code==409
        response=await client.get('/auth/me',headers={'X-Nightly-Run-Grant':REGISTER['grant']})
        assert response.status_code==200 and calls[0]['run']==REGISTER['run']
        row=app.state.nightly_store.engine.rows[('auth',REGISTER['run'])]
        assert list(row['operations'].values())==['done']
        await app.state.nightly_store.command(cmd('seal'));await app.state.nightly_store.command(cmd('retire'))
        assert (await client.get('/auth/me',headers={'X-Nightly-Run-Grant':REGISTER['grant']})).status_code==409
        assert len(calls)==1


@pytest.mark.asyncio
async def test_native_error_keeps_pending_and_cannot_emit_success():
    app,config,calls=setup();app.state.native_error=True
    await app.state.nightly_store.command(REGISTER)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        assert (await client.get('/auth/me',headers={'X-Nightly-Run-Grant':REGISTER['grant']})).status_code==409
    await app.state.nightly_store.command(cmd('seal'))
    with pytest.raises(state.Refused):await app.state.nightly_store.command(cmd('retire'))
    assert admission.get() is None


@pytest.mark.asyncio
async def test_verified_fixture_token_requires_original_run_and_admission(monkeypatch):
    app,config,calls=setup();monkeypatch.setattr('auth_service.nightly_runtime.configuration',lambda:config)
    claims={'sub':SCOPE['subject'],'nightly_run':{'run':REGISTER['run'],'generation':REGISTER['generation']}}
    with pytest.raises(state.Refused):await verify_claims(claims)
    await app.state.nightly_store.command(REGISTER);bound=await app.state.nightly_store.command(cmd('admit'))
    token=admission.set(bound)
    try:
        assert await verify_claims(claims)==claims
        for changed in [claims|{'nightly_run':{'run':'124-1-portal-device-transfer','generation':REGISTER['generation']}}, {'sub':SCOPE['subject']}, {'sub':'unrelated-person'}, claims|{'sub':'unrelated-person'}]:
            with pytest.raises(state.Refused):await verify_claims(changed)
    finally:admission.reset(token)
    assert await verify_claims({'sub':'unrelated-person'})=={'sub':'unrelated-person'}


def test_owner_signature_cannot_authorize_foreign_owner_or_scope():
    app,config,calls=setup();raw=json.dumps(REGISTER).encode()
    wrong=hmac.new(bytes.fromhex(config['ownerKeys']['portal']),raw,hashlib.sha256).hexdigest()
    with pytest.raises(state.Refused):authenticate(config,raw,wrong)
    raw=json.dumps(REGISTER|{'scope':SCOPE|{'subject':'55555555-5555-4555-8555-555555555555'}}).encode()
    signature=hmac.new(bytes.fromhex(config['ownerKeys']['auth']),raw,hashlib.sha256).hexdigest()
    with pytest.raises(state.Refused):authenticate(config,raw,signature)


@pytest.mark.asyncio
@pytest.mark.parametrize('path',['/auth/connect-session-context','/auth/verification-context'])
async def test_specialized_native_session_verifier_refuses_bound_credential_without_admission(monkeypatch,http_client,path):
    app,config,_=setup();monkeypatch.setattr('auth_service.nightly_runtime.configuration',lambda:config)
    claims={'sub':SCOPE['subject'],'tenant_id':SCOPE['tenant'],'nightly_run':{'run':REGISTER['run'],'generation':REGISTER['generation']}}
    monkeypatch.setattr('auth_service.connect_session.try_decode_tenant_session_jwt',lambda token:claims)
    def unexpected():raise AssertionError('no provider or membership call after bound credential refusal')
    monkeypatch.setattr('auth_service.connect_session.get_keycloak_jwt_validator',unexpected)
    response=await http_client.get(path,headers={'Authorization':'Bearer substituted-valid-token','X-Tenant-ID':SCOPE['tenant'],'X-Auth-Session-Token':'substituted-original'})
    assert response.status_code==403


@pytest.mark.asyncio
async def test_closed_native_context_is_never_reused(monkeypatch):
    _,config,_=setup();monkeypatch.setattr('auth_service.nightly_runtime.configuration',lambda:config)
    bound=dict(run=REGISTER['run'],generation=REGISTER['generation'],scope=SCOPE,_closed=True)
    token=admission.set(bound)
    try:
        with pytest.raises(state.Refused):await verify_claims({'sub':SCOPE['subject'],'nightly_run':{'run':REGISTER['run'],'generation':REGISTER['generation']}})
    finally:admission.reset(token)


@pytest.mark.asyncio
async def test_native_tenant_token_preserves_original_admission(monkeypatch):
    import uuid
    from jwt import InvalidTokenError
    from controlplane_identity.nightly import admitted_run
    from controlplane_identity.security.tenant_session_jwt import mint_tenant_session_jwt, try_decode_tenant_session_jwt
    app,config,_=setup()
    claims={'sub':SCOPE['subject'],'nightly_run':{k:REGISTER[k] for k in ('run','generation')}}
    @app.post('/auth/switch-tenant')
    async def mint():
        # Substitute membership and provider only; native signing and verification remain real.
        await verify_claims(claims)
        token=mint_tenant_session_jwt(claims=claims,tenant_id=uuid.UUID(SCOPE['tenant']))
        assert try_decode_tenant_session_jwt(token)['nightly_run']==claims['nightly_run']
        with pytest.raises(InvalidTokenError):
            mint_tenant_session_jwt(claims=claims,tenant_id=uuid.uuid4())
        return {'access_token':token}
    await app.state.nightly_store.command(REGISTER)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        response=await client.post('/auth/switch-tenant',headers={'X-Nightly-Run-Grant':REGISTER['grant']})
    assert response.status_code==200,response.text
    token=response.json()['access_token']
    assert try_decode_tenant_session_jwt(token) is None
    binding=dict(version=1,run='124-1-portal-device-transfer',generation=REGISTER['generation'],scope=SCOPE,operation=str(uuid.uuid4()))
    with admitted_run(binding):assert try_decode_tenant_session_jwt(token) is None
