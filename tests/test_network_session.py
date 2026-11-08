"""Local current network grants never manufacture organization memberships."""
import json
import time
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from starlette.requests import Request
from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt
from auth_service import deps,connect_session as context
from auth_service.network_session import current_network
from auth_service.scoped_session import ScopeUnavailable


@pytest.fixture
def network_owner(monkeypatch):
    for key,value in {'AUTH_SCOPE_AUTHORITY_URL':'https://scope.local','AUTH_SCOPE_AUTHORITY_TOKEN':'local-scope-secret','AUTH_SCOPE_GENERATION':'local-v1','AUTH_SCOPE_MANIFEST_SHA256':'a'*64}.items():monkeypatch.setenv(key,value)
    return dict(subject='local:network-admin',user_id=str(uuid.uuid4()),tenant_id=str(uuid.uuid4()),organization_id=None,network_id='local-network',role='admin',can_purchase=False,generation='local-v1',manifest_sha256='a'*64,permissions=['operator:console','operator:support'])


@respx.mock
async def test_current_network_session_strips_issuer_grants_without_org_membership(app,http_client,network_owner):
    g=network_owner
    async def claims():return dict(sub=g['subject'],azp='controlplane-frontend',permissions=['full_access'],realm_access={'roles':['admin']},groups=['admin'])
    app.dependency_overrides[deps.get_access_token_claims]=claims
    peer=respx.post('https://scope.local/api/v1/internal/network-authority/check').mock(return_value=httpx.Response(200,json=g))
    try:
        response=await http_client.post('/auth/network-session',headers={'Authorization':'Bearer local-issuer'},json={'tenant_id':g['tenant_id']})
        assert response.status_code==200,response.text
        token=try_decode_tenant_session_jwt(response.json()['access_token'])
        assert token['realm_access']['roles']==['network:admin'] and token['permissions']==g['permissions'] and token['groups']==[]
        assert token['organization_id'] is None and token['scope_kind']=='network'
        assert token['scope_generation']=='local-v1' and token['network_id']==g['network_id']
        assert response.headers['cache-control']=='no-store'
        request=peer.calls.last.request
        assert request.headers['authorization']=='Bearer local-scope-secret'
        assert json.loads(request.content)=={'subject':g['subject'],'tenant_id':g['tenant_id']}
    finally:app.dependency_overrides.pop(deps.get_access_token_claims,None)


@pytest.mark.parametrize('change',[{'subject':'other'},{'tenant_id':str(uuid.uuid4())},{'generation':'stale'},{'manifest_sha256':'b'*64},{'organization_id':str(uuid.uuid4())},{'permissions':['full_access']},{'permissions':['operator:console','operator:console']},{'can_purchase':True},{'can_purchase':0},{'role':'member'},{'extra':'grant'}])
@respx.mock
async def test_network_client_refuses_mismatched_or_elevated_owner_reply(network_owner,change):
    g=network_owner
    respx.post('https://scope.local/api/v1/internal/network-authority/check').mock(return_value=httpx.Response(200,json={**g,**change}))
    with pytest.raises(ScopeUnavailable):await current_network(g['subject'],uuid.UUID(g['tenant_id']))


@pytest.mark.parametrize('reply',[None,401,403,307,500])
@respx.mock
async def test_network_denial_is_distinct_from_owner_outage(network_owner,reply):
    g=network_owner
    respx.post('https://scope.local/api/v1/internal/network-authority/check').mock(return_value=httpx.Response(200,content='null') if reply is None else httpx.Response(reply))
    if reply is None:assert await current_network(g['subject'],uuid.UUID(g['tenant_id'])) is None
    else:
        with pytest.raises(ScopeUnavailable):await current_network(g['subject'],uuid.UUID(g['tenant_id']))


@pytest.mark.parametrize('result',['allow','revoked','outage','different-network','malformed-scope'])
@respx.mock
async def test_network_connect_rechecks_current_authority(network_owner,monkeypatch,result):
    g=network_owner;now=int(time.time())
    tenant=dict(sub=g['subject'],tenant_id=g['tenant_id'],spanopticon_auth='tenant_session',azp='controlplane-frontend',scope_version=1,scope_kind='network',organization_id=None,network_id=g['network_id'],scope_generation=g['generation'],scope_manifest_sha256=g['manifest_sha256'])
    if result=='malformed-scope':tenant['organization_id']=str(uuid.uuid4())
    origin=dict(iss=context.settings.keycloak_issuer.rstrip('/'),sub=g['subject'],azp='controlplane-frontend',sid='local-session',exp=now+300,iat=now,auth_time=now,acr='1',amr=['pwd'])
    monkeypatch.setattr(context,'try_decode_tenant_session_jwt',lambda t:tenant)
    monkeypatch.setattr(context,'get_keycloak_jwt_validator',lambda:type('Validator',(),{'validate':AsyncMock(return_value=origin)})())
    monkeypatch.setattr(context,'confidential_introspection_credentials',lambda:('local','secret'))
    monkeypatch.setattr(context,'introspect_access_token',AsyncMock(return_value={'active':True,'sub':g['subject'],'client_id':'controlplane-frontend'}))
    peer=respx.post('https://scope.local/api/v1/internal/network-authority/check')
    if result=='outage':peer.mock(return_value=httpx.Response(503))
    else:peer.mock(return_value=httpx.Response(200,content='null' if result=='revoked' else json.dumps({**g,'network_id':'other-network'} if result=='different-network' else g)))
    request=Request({'type':'http','headers':[(b'authorization',b'Bearer local-network'),(b'x-tenant-id',g['tenant_id'].encode()),(b'x-auth-session-token',b'local-browser')]})
    response=await context.connect_session_context(request)
    assert response.status_code=={'allow':200,'revoked':403,'outage':503,'different-network':403,'malformed-scope':403}[result]
    payload=json.loads(response.body)
    if result=='allow':assert payload['organization_id'] is None and payload['scope_kind']=='network' and payload['second_factor_at'] is None
    assert (payload.get('code')=='membership_revoked')==(result=='revoked')
