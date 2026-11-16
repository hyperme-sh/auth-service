"""Native startup route/selection; verified provider claims, User HTTP and DB are substitutes."""
import copy
import json
from pathlib import Path
import httpx
import pytest
import respx
from fastapi import FastAPI
from controlplane_identity import nightly
from auth_service import deps, startup_identity
from auth_service._startup_contract import fingerprint
from auth_service.startup_routes import router
from auth_service.nightly_middleware import NightlyMiddleware
from auth_service.nightly_store import PostgresNightlyStore
from test_nightly_state import SCOPE, REGISTER
from test_nightly_store import Engine


@pytest.mark.parametrize('refusal',[None,'subject','generation','tenant','sea','suite','issuer','client'])
@respx.mock(assert_all_called=False)
async def test_startup_native_read_is_bound_before_user_lookup(monkeypatch,refusal):
    config=json.loads(Path(__file__).with_name('fixtures').joinpath('startup-identity.json').read_text())
    config['owner']['broker']={'issuer':SCOPE['issuer'],'audience':'s3rch'}
    scope={**copy.deepcopy(SCOPE),'suite':'flags-s3rch-browser','tenant':config['owner']['tenant_id'],
           'clients':['s3rch'],'origins':['https://test.s3r.ch'],'identities':{'sea':[config['binding']['sea_public_key']]}}
    if refusal=='tenant':scope['tenant']=SCOPE['tenant']
    if refusal=='sea':scope['identities']['sea']=[]
    if refusal=='suite':scope['suite']='s3rch-device-transfer'
    if refusal=='issuer':config['owner']['broker']['issuer']='https://foreign.example.invalid/realms/test'
    if refusal=='client':scope['clients']=['another-client']
    registration={**REGISTER,'run':'123-1-'+scope['suite'],'scope':scope}
    claims={'sub':scope['subject'],'iss':config['owner']['broker']['issuer'],'aud':'s3rch',
            'login_provider':config['binding']['entra']['broker'],
            'entra_tenant_id':config['binding']['entra']['tenant_id'],'entra_object_id':config['binding']['entra']['object_id'],
            'nightly_run':{k:registration[k] for k in ('run','generation')}}
    if refusal=='subject':claims['sub']='foreign-subject'
    if refusal=='generation':claims['nightly_run']['generation']='f'*64
    monkeypatch.setattr(nightly,'_subjects',frozenset())
    monkeypatch.setattr(startup_identity,'configuration',lambda:config)
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_URL','https://owner.example.invalid')
    monkeypatch.setenv('USER_STARTUP_READ_TOKEN','isolated-read-token')
    person={'schema_version':1,'mapping_sha256':fingerprint(config),'status':'reconciled',
            'person_id':'00000000-0000-4000-8000-000000000110','broker_subject':scope['subject'],
            'tenant_id':config['owner']['tenant_id'],'network_id':config['owner']['network_id'],
            'organizations':[{'slug':s,'id':o['organization_id'],'tenant_id':o['tenant_id'],'roles':o['roles']}
                             for s,o in sorted(config['binding']['organizations'].items())]}
    peer=respx.post('https://owner.example.invalid/api/v1/internal/startup/status').mock(return_value=httpx.Response(200,json=person))
    app=FastAPI();app.include_router(router,prefix='/auth');app.add_middleware(NightlyMiddleware)
    app.state.nightly_config={'scopes':{scope['suite']:scope}}
    store=app.state.nightly_store=PostgresNightlyStore(Engine(),app.state.nightly_config['scopes'])
    await store.command(registration)
    async def verified():return claims
    app.dependency_overrides[deps.get_access_token_claims]=verified
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url='https://auth.unit') as client:
        headers={'X-Nightly-Run-Grant':registration['grant']}
        response=await client.get('/auth/startup/identity',headers=headers)
        row=store.engine.rows[('auth',registration['run'])]
        assert response.status_code==(409 if refusal else 200),response.text
        assert list(row['operations'].values())==(['pending'] if refusal else ['done'])
        assert peer.call_count==(0 if refusal else 1)
        if not refusal:
            assert response.json()['sea_public_key']==config['binding']['sea_public_key']
            assert peer.calls.last.request.headers['Authorization']=='Bearer isolated-read-token'
            assert 'X-Nightly-Run-Grant' not in peer.calls.last.request.headers
        await store.command({k:registration[k] for k in ('version','owner','run','generation','fence')}|{'action':'seal'})
        assert (await client.get('/auth/startup/identity',headers=headers)).status_code==409
        assert (await client.post('/auth/startup/reconcile',headers=headers,json={})).status_code==409
        assert (await client.post('/auth/startup/status',headers=headers,json={})).status_code==409
        assert peer.call_count==(0 if refusal else 1)
