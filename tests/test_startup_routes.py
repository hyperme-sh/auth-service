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
    monkeypatch.delenv('AUTH_SCOPE_GENERATION',raising=False)
    monkeypatch.delenv('AUTH_SCOPE_MANIFEST_SHA256',raising=False)
    assert owner_configuration()==('https://scope.example.invalid','scoped-reader','startup-v1',fingerprint(startup_config))


@pytest.mark.parametrize('generation',['existing-authority','startup-v1'])
@respx.mock
async def test_startup_scope_preserves_existing_owner_generation(startup_config,monkeypatch,generation):
    import uuid
    from auth_service.scoped_session import current_scope,ScopeUnavailable
    c=startup_config;org=next(iter(c['binding']['organizations'].values()))
    monkeypatch.setenv('AUTH_SCOPE_AUTHORITY_URL','https://scope.example.invalid')
    monkeypatch.setenv('AUTH_SCOPE_AUTHORITY_TOKEN','scoped-reader')
    monkeypatch.setenv('AUTH_SCOPE_GENERATION','existing-authority')
    monkeypatch.setenv('AUTH_SCOPE_MANIFEST_SHA256','1'*64)
    grant={'subject':'selected','user_id':'00000000-0000-4000-8000-000000000110','tenant_id':org['tenant_id'],
        'organization_id':org['organization_id'],'network_id':c['owner']['network_id'],'role':'admin','can_purchase':False,
        'generation':generation,'manifest_sha256':fingerprint(c) if generation=='startup-v1' else '1'*64}
    peer=respx.post('https://scope.example.invalid/api/v1/internal/organization-authority/check')
    peer.mock(return_value=httpx.Response(200,json=grant))
    result=await current_scope('selected',uuid.UUID(org['tenant_id']),uuid.UUID(org['organization_id']))
    assert result.generation==generation
    peer.mock(return_value=httpx.Response(200,json={**grant,'manifest_sha256':'0'*64}))
    with pytest.raises(ScopeUnavailable):await current_scope('selected',uuid.UUID(org['tenant_id']),uuid.UUID(org['organization_id']))


@respx.mock
async def test_github_member_resolves_only_existing_membership(http_client, startup_config, tmp_path, monkeypatch):
    from types import SimpleNamespace
    from time import time
    from jwt import encode
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    from auth_service import startup_github_member as github
    from auth_service.session_membership import MemberGrant
    from uuid import UUID

    subject = '00000000-0000-4000-8000-000000000121'
    person = '00000000-0000-4000-8000-000000000122'
    tenant = startup_config['owner']['tenant_id']
    mapping = {
        'version': 1, 'environment': 'test', 'tenant_id': tenant, 'network_id': 'hyperme.sh',
        'broker': {'issuer': github.ISSUER, 'audience': github.AUDIENCE, 'subject': subject, 'provider': 'github'},
        'sea_public_key': startup_config['binding']['sea_public_key'],
    }
    config = tmp_path / 'github-member.json'
    config.write_text(json.dumps(mapping) + '\n')
    config.chmod(0o600)
    monkeypatch.setattr(github, 'settings', SimpleNamespace(keycloak_issuer=github.ISSUER))
    monkeypatch.setattr(github, 'require_open_account', lambda claims: None)
    member = AsyncMock(return_value=MemberGrant(user_id=UUID(person)))
    monkeypatch.setattr(github, 'authorize_session_member', member)
    key = generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(github.JWKS, 'get_signing_key_from_jwt', lambda token: SimpleNamespace(key=key.public_key()))
    now = int(time())
    claims = {'iss': github.ISSUER, 'aud': github.AUDIENCE, 'azp': github.AUDIENCE,
              'sub': subject, 'login_provider': 'github', 'typ': 'Bearer', 'amr': ['mfa'],
              'iat': now, 'exp': now + 60}
    url = '/auth/startup/identity/github-member'

    async def request(overrides):
        token = encode(claims | overrides, key, algorithm='RS256')
        return await http_client.get(url, headers={'Authorization': 'Bearer ' + token})

    assert (await request({})).status_code == 403
    monkeypatch.setenv('STARTUP_TEST_GITHUB_MEMBER_CONFIG_FILE', str(config))
    for wrong in ({'sub': person}, {'azp': 'controlplane-frontend'}, {'aud': 'account'},
                  {'login_provider': 'microsoft'}, {'typ': 'ID'}, {'exp': now - 5}):
        assert (await request(wrong)).status_code == 403
    member.assert_not_awaited()
    response = await request({})
    assert response.status_code == 200, response.text
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.json()['person_id'] == person
    assert response.json()['permissions'] == response.json()['organizations'] == []
    assert response.json()['github'] == {'subject': subject}
    assert 'entra' not in response.json()
    member.assert_awaited_once_with(subject, UUID(tenant))
    monkeypatch.delenv('STARTUP_TEST_GITHUB_MEMBER_CONFIG_FILE')
    monkeypatch.setenv('STARTUP_TEST_GITHUB_MEMBER_CONFIG', config.read_text().rstrip('\n'))
    env_response = await request({})
    assert env_response.status_code == 200
    assert env_response.json()['mapping_sha256'] == response.json()['mapping_sha256']
    member.return_value = None
    assert (await request({})).status_code == 403


async def test_nightly_member_requires_its_configured_broker_and_client(startup_config, monkeypatch):
    from time import time
    from types import SimpleNamespace
    from uuid import UUID

    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    from fastapi import HTTPException, Response
    from jwt import encode

    from auth_service import claims as auth_claims, startup_github_member as member_auth
    from auth_service.session_membership import MemberGrant
    from auth_service.startup_routes import resolve_nightly_member

    subject = '00000000-0000-4000-8000-000000000121'
    person = '00000000-0000-4000-8000-000000000122'
    tenant = startup_config['owner']['tenant_id']
    audience = 's3rch-startup-nightly'
    provider = 'startup-nightly'
    mapping = {
        'version': 1, 'environment': 'test', 'tenant_id': tenant, 'network_id': 'hyperme.sh',
        'broker': {'issuer': member_auth.ISSUER, 'audience': audience, 'subject': subject, 'provider': provider},
        'sea_public_key': startup_config['binding']['sea_public_key'],
    }
    settings = SimpleNamespace(keycloak_issuer=member_auth.ISSUER)
    monkeypatch.setattr(member_auth, 'settings', settings)
    monkeypatch.setattr(member_auth, 'require_open_account', lambda claims: None)
    monkeypatch.setattr(auth_claims, 'settings', SimpleNamespace(oidc_require_mfa=True))
    member = AsyncMock(return_value=MemberGrant(user_id=UUID(person)))
    monkeypatch.setattr(member_auth, 'authorize_session_member', member)
    key = generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(member_auth.JWKS, 'get_signing_key_from_jwt', lambda token: SimpleNamespace(key=key.public_key()))
    now = int(time())
    claims = {'iss': member_auth.ISSUER, 'aud': audience, 'azp': audience, 'sub': subject,
              'login_provider': provider, 'typ': 'Bearer', 'amr': ['otp'], 'iat': now, 'exp': now + 60}

    async def resolve(overrides, response=None):
        return await resolve_nightly_member(response or Response(), encode(claims | overrides, key, algorithm='RS256'))

    with pytest.raises(HTTPException) as unavailable:
        await resolve({})
    assert unavailable.value.status_code == 403
    monkeypatch.setenv('STARTUP_TEST_NIGHTLY_MEMBER_CONFIG', json.dumps(mapping))
    for wrong in ({'sub': person}, {'azp': 's3rch-web'}, {'aud': 's3rch-web'}, {'login_provider': 'github'},
                  {'typ': 'ID'}, {'amr': ['pwd']}, {'email': 'same@example.invalid', 'sub': person}):
        with pytest.raises(HTTPException) as denied:
            await resolve(wrong)
        assert denied.value.status_code == 403
    member.assert_not_awaited()
    response = Response()
    result = await resolve({}, response)
    assert response.headers['Cache-Control'] == 'no-store'
    assert result['oidc'] == {'provider': provider, 'subject': subject}
    assert result['person_id'] == person
    assert result['permissions'] == result['organizations'] == []
    assert 'github' not in result
    member.assert_awaited_once_with(subject, UUID(tenant))
    settings.keycloak_issuer = 'https://auth.hyperme.sh/realms/controlplane'
    with pytest.raises(HTTPException) as production:
        await resolve({})
    assert production.value.status_code == 403
