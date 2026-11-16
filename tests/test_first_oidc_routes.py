"""Protected configuration and ASGI first-link boundary contracts, CI only."""
import asyncio
import importlib.util
import json
from pathlib import Path
import time
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from httpx import ASGITransport,AsyncClient
import pytest
from auth_service import first_oidc_runtime as runtime,first_oidc_link as core
from auth_service.first_oidc_routes import router

spec=importlib.util.spec_from_file_location('first_oidc_fixture_routes',Path(__file__).with_name('test_first_oidc_link.py'))
fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)

@pytest.mark.asyncio
async def test_default_off_private_file_and_bounded_route(tmp_path,monkeypatch):
    app=FastAPI();app.include_router(router);app.state.first_oidc_slots=asyncio.Semaphore(2);app.state.async_engine=object()
    monkeypatch.delenv('AUTH_FIRST_OIDC_LINK_CONFIG_FILE',raising=False)
    monkeypatch.delenv('AUTH_NIGHTLY_RUN_CONFIG_FILE',raising=False)
    async with AsyncClient(transport=ASGITransport(app=app),base_url='https://auth.example') as client:
        for action in ('issue','cancel'):assert (await client.post('/auth/first-oidc-link/v1/'+action,json={})).status_code==503
        r,b,j,k,signer,token,_=fixtures.fixture(int(time.time()))
        config=dict(version=1,serviceToken='s'*43,bindings=[b],providerJwks=j,signer=k,
                    signingKeyPem=signer.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
        path=tmp_path/'private.json';path.write_text(json.dumps(config));path.chmod(0o600)
        monkeypatch.setenv('AUTH_FIRST_OIDC_LINK_CONFIG_FILE',str(path));assert runtime.configuration()==config
        headers={'authorization':'Bearer '+'s'*43};body={'record':r,'idToken':token()}
        calls=[]
        async def issue(self,*args):calls.append('issue');args[-1]();return 'synthetic-output'
        async def cancel(self,*args):calls.append('cancel');args[-1]();return 'cancelled'
        monkeypatch.setattr('auth_service.first_oidc_routes.FirstOidcStore.issue',issue)
        monkeypatch.setattr('auth_service.first_oidc_routes.FirstOidcStore.cancel',cancel)
        response=await client.post('/auth/first-oidc-link/v1/issue',json=body,headers=headers)
        assert response.json()=={'version':1,'attestation':'synthetic-output'}
        assert response.headers['cache-control']=='private, no-store'
        assert (await client.post('/auth/first-oidc-link/v1/cancel',json={'record':r},headers=headers)).json()=={'version':1,'status':'cancelled'}
        for bad_headers,bad_body in [({},body),(headers|{'x-nightly-run-grant':'not-registered'},body),(headers,body|{'principal':'override'}),(headers,{'record':r|{'principal':'other'},'idToken':'secret'})]:
            response=await client.post('/auth/first-oidc-link/v1/issue',json=bad_body,headers=bad_headers)
            assert response.status_code==409 and 'secret' not in response.text
        assert calls==['issue','cancel']
        path.chmod(0o644)
        with pytest.raises(core.FirstLinkRefused):runtime.configuration()
        path.chmod(0o600);link=tmp_path/'alias';link.symlink_to(path);monkeypatch.setenv('AUTH_FIRST_OIDC_LINK_CONFIG_FILE',str(link))
        with pytest.raises(core.FirstLinkRefused):runtime.configuration()

@pytest.mark.asyncio
@pytest.mark.parametrize('refusal',[None,'missing-run','foreign-run','missing-grant','foreign-tenant','foreign-client','foreign-issuer'])
async def test_native_first_link_admits_only_original_managed_run(monkeypatch,refusal):
    from auth_service import nightly_runtime as nightly
    from auth_service.nightly_middleware import NightlyMiddleware
    from auth_service.nightly_store import PostgresNightlyStore
    from test_nightly_state import REGISTER,SCOPE,cmd
    from test_nightly_store import Engine
    r,b,j,k,signer,token,claims=fixtures.fixture(int(time.time()),subject=SCOPE['subject'],tenant=SCOPE['tenant'],issuer=SCOPE['issuer'],clientId=SCOPE['clients'][0])
    config=dict(version=1,serviceToken='s'*43,bindings=[b],providerJwks=j,signer=k,
        signingKeyPem=signer.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
    scope=dict(SCOPE)
    if refusal=='foreign-tenant':scope['tenant']='33333333-3333-4333-8333-333333333333'
    if refusal=='foreign-client':scope['clients']=['another-client']
    if refusal=='foreign-issuer':b['issuer']='https://foreign.example'
    registration=REGISTER|{'scope':scope}
    native={'scopes':{scope['suite']:scope}}
    monkeypatch.setattr(runtime,'configuration',lambda:config)
    monkeypatch.setattr(nightly,'configuration',lambda:native)
    app=FastAPI();app.include_router(router);app.add_middleware(NightlyMiddleware)
    app.state.first_oidc_slots=asyncio.Semaphore(2);app.state.async_engine=object()
    app.state.nightly_config=native;app.state.nightly_store=PostgresNightlyStore(Engine(),native['scopes'])
    await app.state.nightly_store.command(registration)
    calls=[]
    async def issue(self,*args):calls.append('issue');args[-1]();return 'synthetic-output'
    async def cancel(self,*args):calls.append('cancel');args[-1]();return 'cancelled'
    monkeypatch.setattr('auth_service.first_oidc_routes.FirstOidcStore.issue',issue)
    monkeypatch.setattr('auth_service.first_oidc_routes.FirstOidcStore.cancel',cancel)
    claims=claims|{'nightly_run':{k:REGISTER[k] for k in ('run','generation')}}
    if refusal=='missing-run':claims.pop('nightly_run')
    if refusal=='foreign-run':claims['nightly_run']['generation']='d'*64
    headers={'authorization':'Bearer '+'s'*43,'X-Nightly-Run-Grant':REGISTER['grant']}
    if refusal=='missing-grant':headers.pop('X-Nightly-Run-Grant')
    async with AsyncClient(transport=ASGITransport(app=app),base_url='https://auth.example') as client:
        response=await client.post('/auth/first-oidc-link/v1/issue',json={'record':r,'idToken':token(claims)},headers=headers)
        assert response.status_code==(409 if refusal else 200),response.text
        assert calls==([] if refusal else ['issue'])
        if not refusal:
            response=await client.post('/auth/first-oidc-link/v1/cancel',json={'record':r},headers=headers)
            assert response.status_code==200
            await app.state.nightly_store.command(cmd('seal'))
            for action,body in [('issue',{'record':r,'idToken':token(claims)}),('cancel',{'record':r})]:
                assert (await client.post('/auth/first-oidc-link/v1/'+action,json=body,headers=headers)).status_code==409
            await app.state.nightly_store.command(cmd('retire'))
            assert (await client.post('/auth/first-oidc-link/v1/issue',json={'record':r,'idToken':token(claims)},headers=headers)).status_code==409
            assert calls==['issue','cancel']
