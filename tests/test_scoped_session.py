"""Local contract tests; shared TEST accounts are not used or provisioned."""
import json
import time
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt
from auth_service import deps, connect_session as context
from auth_service.scoped_session import current_scope, ScopeUnavailable
from starlette.requests import Request


@pytest.fixture
def scoped_owner(monkeypatch):
    for k,v in {'AUTH_SCOPE_AUTHORITY_URL':'https://scope.local','AUTH_SCOPE_AUTHORITY_TOKEN':'local-scope-secret','AUTH_SCOPE_GENERATION':'local-v1','AUTH_SCOPE_MANIFEST_SHA256':'a'*64}.items():monkeypatch.setenv(k,v)
    tenant,org,user=uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
    return {'subject':'local:subject','user_id':str(user),'tenant_id':str(tenant),'organization_id':str(org),'network_id':'local-network','role':'admin','can_purchase':True,'generation':'local-v1','manifest_sha256':'a'*64}


@respx.mock
async def test_scoped_session_mints_only_current_org_authority(app,http_client,scoped_owner):
    g=scoped_owner
    async def claims():return {'sub':g['subject'],'email':'local@example.invalid','azp':'controlplane-frontend','realm_access':{'roles':['admin']},'permissions':['full_access'],'groups':['admin']}
    app.dependency_overrides[deps.get_access_token_claims]=claims
    peer=respx.post('https://scope.local/api/v1/internal/organization-authority/check').mock(return_value=httpx.Response(200,json=g))
    try:
        r=await http_client.post('/auth/scoped-session',headers={'Authorization':'Bearer local-browser'},json={'tenant_id':g['tenant_id'],'organization_id':g['organization_id']})
        assert r.status_code==200,r.text
        token=try_decode_tenant_session_jwt(r.json()['access_token'])
        assert token['realm_access']['roles']==['org:admin'] and token['permissions']==[] and token['groups']==[]
        assert token['organization_id']==g['organization_id'] and token['network_id']==g['network_id']
        assert token['scope_generation']=='local-v1' and token['scope_manifest_sha256']=='a'*64
        assert 'can_purchase' not in token  # Billing authority must be checked live by its owner.
        assert r.headers['cache-control']=='no-store'
        sent=peer.calls.last.request
        assert sent.headers['authorization']=='Bearer local-scope-secret'
        assert 'local-browser' not in sent.content.decode()
        assert json.loads(sent.content)=={'subject':g['subject'],'tenant_id':g['tenant_id'],'organization_id':g['organization_id'],'capability':'member'}
    finally:app.dependency_overrides.pop(deps.get_access_token_claims,None)


@pytest.mark.parametrize('change',[{'subject':'someone-else'},{'tenant_id':str(uuid.uuid4())},{'organization_id':str(uuid.uuid4())},{'generation':'stale'},{'manifest_sha256':'b'*64},{'role':'network-admin'},{'can_purchase':'yes'},{'extra':'admin'}])
@respx.mock
async def test_scope_client_refuses_mismatched_or_malformed_grants(scoped_owner,change):
    g=scoped_owner
    respx.post('https://scope.local/api/v1/internal/organization-authority/check').mock(return_value=httpx.Response(200,json={**g,**change}))
    with pytest.raises(ScopeUnavailable):await current_scope(g['subject'],uuid.UUID(g['tenant_id']),uuid.UUID(g['organization_id']))


@pytest.mark.parametrize('reply',[None,401,403,307,500])
@respx.mock
async def test_scope_denial_and_transport_failures_are_distinct(scoped_owner,reply):
    g=scoped_owner
    respx.post('https://scope.local/api/v1/internal/organization-authority/check').mock(return_value=httpx.Response(200,content='null') if reply is None else httpx.Response(reply))
    if reply is None:assert await current_scope(g['subject'],uuid.UUID(g['tenant_id']),uuid.UUID(g['organization_id'])) is None
    else:
        with pytest.raises(ScopeUnavailable):await current_scope(g['subject'],uuid.UUID(g['tenant_id']),uuid.UUID(g['organization_id']))


@pytest.mark.parametrize('result',['allow','revoked','outage','different-network'])
@respx.mock
async def test_scoped_context_rechecks_current_owner(scoped_owner,monkeypatch,result):
    g=scoped_owner;now=int(time.time())
    tenant={'sub':g['subject'],'tenant_id':g['tenant_id'],'spanopticon_auth':'tenant_session','azp':'controlplane-frontend','scope_version':1,'organization_id':g['organization_id'],'network_id':g['network_id'],'scope_generation':g['generation'],'scope_manifest_sha256':g['manifest_sha256']}
    origin={'iss':context.settings.keycloak_issuer.rstrip('/'),'sub':g['subject'],'azp':'controlplane-frontend','sid':'local-session','exp':now+300,'iat':now,'auth_time':now,'acr':'1','amr':['pwd']}
    monkeypatch.setattr(context,'try_decode_tenant_session_jwt',lambda t:tenant)
    monkeypatch.setattr(context,'get_keycloak_jwt_validator',lambda:type('Validator',(),{'validate':AsyncMock(return_value=origin)})())
    monkeypatch.setattr(context,'confidential_introspection_credentials',lambda:('local','secret'))
    monkeypatch.setattr(context,'introspect_access_token',AsyncMock(return_value={'active':True,'sub':g['subject'],'client_id':'controlplane-frontend'}))
    peer=respx.post('https://scope.local/api/v1/internal/organization-authority/check')
    if result=='outage':peer.mock(return_value=httpx.Response(503))
    else:peer.mock(return_value=httpx.Response(200,content='null' if result=='revoked' else json.dumps({**g,'network_id':'wrong'} if result=='different-network' else g)))
    request=Request({'type':'http','headers':[(b'authorization',b'Bearer local-tenant'),(b'x-tenant-id',g['tenant_id'].encode()),(b'x-auth-session-token',b'local-browser')]})
    response=await context.connect_session_context(request)
    assert response.status_code=={'allow':200,'revoked':403,'outage':503,'different-network':403}[result]
    payload=json.loads(response.body)
    if result=='allow':assert payload['organization_id']==g['organization_id'] and payload['second_factor_at'] is None
    assert (payload.get('code')=='membership_revoked')==(result=='revoked')


@pytest.mark.parametrize('url',['http://scope.local','https://user:password@scope.local','https://scope.local?secret=value'])
async def test_scope_credentials_require_verified_tls_endpoint(scoped_owner,monkeypatch,url):
    g=scoped_owner;monkeypatch.setenv('AUTH_SCOPE_AUTHORITY_URL',url)
    with pytest.raises(ScopeUnavailable):await current_scope(g['subject'],uuid.UUID(g['tenant_id']),uuid.UUID(g['organization_id']))


@pytest.mark.parametrize('client_fields',[{'client_id':'controlplane-m2m'},{'azp':'controlplane-mobile'}])
@respx.mock
async def test_scoped_session_preserves_verified_client_identity(app,http_client,scoped_owner,client_fields):
    g=scoped_owner
    async def claims():return {'sub':g['subject'],**client_fields}
    app.dependency_overrides[deps.get_access_token_claims]=claims
    respx.post('https://scope.local/api/v1/internal/organization-authority/check').mock(return_value=httpx.Response(200,json=g))
    try:
        r=await http_client.post('/auth/scoped-session',headers={'Authorization':'Bearer local-issuer'},json={'tenant_id':g['tenant_id'],'organization_id':g['organization_id']})
        assert r.status_code==200,r.text
        signed=try_decode_tenant_session_jwt(r.json()['access_token'])
        assert signed['azp']==next(iter(client_fields.values()))
        assert signed['azp']!='controlplane-frontend'
    finally:app.dependency_overrides.pop(deps.get_access_token_claims,None)


@pytest.mark.parametrize('client_fields',[{}, {'azp':'controlplane-frontend','client_id':'other-client'}, {'azp':123}])
@respx.mock
async def test_missing_or_conflicting_client_cannot_reach_scope_owner(app,http_client,scoped_owner,client_fields):
    g=scoped_owner
    async def claims():return {'sub':g['subject'],**client_fields}
    app.dependency_overrides[deps.get_access_token_claims]=claims
    try:
        r=await http_client.post('/auth/scoped-session',headers={'Authorization':'Bearer local-issuer'},json={'tenant_id':g['tenant_id'],'organization_id':g['organization_id']})
        assert r.status_code==403 and r.headers['cache-control']=='no-store'
    finally:app.dependency_overrides.pop(deps.get_access_token_claims,None)
