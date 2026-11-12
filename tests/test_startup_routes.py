"""Startup route contracts preserve the existing verified-claims dependency."""
import json
from pathlib import Path
from unittest.mock import AsyncMock
import httpx
import pytest
import respx
from auth_service import deps, startup_identity
from auth_service._startup_contract import fingerprint


@pytest.fixture
def startup_config(tmp_path,monkeypatch):
    config=json.loads(Path(__file__).with_name('fixtures').joinpath('startup-identity.json').read_text())
    path=tmp_path/'mapping.json';path.write_text(json.dumps(config));path.chmod(0o600)
    for key,value in {'STARTUP_IDENTITY_ENABLED':'1','STARTUP_IDENTITY_CONFIG_FILE':str(path),'AUTH_STARTUP_TOKEN':'unit-writer',
        'AUTH_IDENTITY_OWNER_URL':'https://owner.example.invalid','AUTH_IDENTITY_OWNER_TOKEN':'unit-binder','USER_STARTUP_READ_TOKEN':'unit-reader'}.items():
        monkeypatch.setenv(key,value)
    return config


async def test_startup_route_refuses_browser_and_wrong_configuration(app,http_client,startup_config,monkeypatch):
    action=AsyncMock();monkeypatch.setattr(startup_identity,'reconcile',action)
    for token,sha,status in [('browser','0'*64,401),('unit-writer','0'*64,409)]:
        response=await http_client.post('/auth/startup/reconcile',headers={'Authorization':'Bearer '+token},json={'mapping_sha256':sha})
        assert response.status_code==status
    action.assert_not_called()


@respx.mock
async def test_startup_login_cannot_bind_and_wrong_subject_is_refused(app,http_client,startup_config):
    c=startup_config
    person={'schema_version':1,'mapping_sha256':fingerprint(c),'status':'reconciled','person_id':'00000000-0000-4000-8000-000000000110',
        'broker_subject':'expected','tenant_id':c['owner']['tenant_id'],'network_id':c['owner']['network_id'],
        'organizations':[{'slug':s,'id':o['organization_id'],'tenant_id':o['tenant_id'],'roles':o['roles']} for s,o in sorted(c['binding']['organizations'].items())]}
    peer=respx.post('https://owner.example.invalid/api/v1/internal/startup/status').mock(return_value=httpx.Response(200,json=person))
    claims={'iss':c['owner']['broker']['issuer'],'aud':c['owner']['broker']['audience'],'sub':'expected','login_provider':'startup-microsoft','entra_tenant_id':c['binding']['entra']['tenant_id'],'entra_object_id':c['binding']['entra']['object_id']}
    async def verified():return dict(claims)
    app.dependency_overrides[deps.get_access_token_claims]=verified
    try:
        result=await http_client.get('/auth/startup/identity')
        assert result.status_code==200,result.text
        assert result.json()['permissions']==[]
        assert peer.calls.last.request.headers['authorization']=='Bearer unit-reader'
        claims['sub']='attacker'
        assert (await http_client.get('/auth/startup/identity')).status_code==403
        assert len(peer.calls)==2
    finally:app.dependency_overrides.pop(deps.get_access_token_claims,None)


async def test_startup_disables_historical_tenant_promotion(app,http_client,startup_config,monkeypatch):
    async def claims():return {'sub':'configured','email':startup_config['owner']['profile']['email']}
    app.dependency_overrides[deps.get_access_token_claims]=claims
    try:
        response=await http_client.post('/auth/switch-tenant',json={'tenant_id':startup_config['owner']['tenant_id']})
        assert response.status_code==403
    finally:app.dependency_overrides.pop(deps.get_access_token_claims,None)


def test_startup_scope_seal_comes_from_private_mapping(startup_config,monkeypatch):
    from auth_service.scoped_session import owner_configuration
    monkeypatch.setenv('AUTH_SCOPE_AUTHORITY_URL','https://scope.example.invalid')
    monkeypatch.setenv('AUTH_SCOPE_AUTHORITY_TOKEN','scoped-reader')
    monkeypatch.setenv('AUTH_SCOPE_GENERATION','unrelated')
    monkeypatch.setenv('AUTH_SCOPE_MANIFEST_SHA256','0'*64)
    assert owner_configuration()==('https://scope.example.invalid','scoped-reader','startup-v1',fingerprint(startup_config))
