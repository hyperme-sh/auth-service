"""Live membership denial and owner outage must remain distinct context facts."""
import json
import time
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from starlette.requests import Request
from auth_service import connect_session as context


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_URL','https://user-owner.test')
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_TOKEN','fixture-owner-token')


@respx.mock
async def test_current_member_sends_only_exact_subject_and_scope(owner):
    member,tenant=uuid.uuid4(),uuid.uuid4()
    peer=respx.post('https://user-owner.test/api/v1/internal/identity/session-member').mock(return_value=httpx.Response(200,json={'user_id':str(member)}))
    assert await context.current_member(tenant,'opaque:subject')==str(member)
    request=peer.calls.last.request
    assert json.loads(request.content)=={'subject':'opaque:subject','tenant_id':str(tenant)}
    assert request.headers['authorization']=='Bearer fixture-owner-token'
    assert 'x-auth-session-token' not in request.headers


@pytest.mark.parametrize('body',[None,{},[],False,{'user_id':'bad'},{'user_id':str(uuid.uuid4()),'role':'admin'}])
@pytest.mark.parametrize('endpoint',['connect','verification'])
@respx.mock
async def test_context_distinguishes_owner_denial_from_malformed_authority(owner,monkeypatch,body,endpoint):
    tenant=str(uuid.uuid4()); now=int(time.time())
    monkeypatch.setattr(context,'try_decode_tenant_session_jwt',lambda token:{'tenant_id':tenant,'sub':'subject','spanopticon_auth':'tenant_session','azp':'controlplane-frontend'})
    origin={'iss':context.settings.keycloak_issuer.rstrip('/'),'sub':'subject','azp':'controlplane-frontend','sid':'session',
            'exp':now+300,'iat':now,'auth_time':now,'acr':'2','amr':['pwd','otp']}
    monkeypatch.setattr(context,'get_keycloak_jwt_validator',lambda:type('Validator',(),{'validate':AsyncMock(return_value=origin)})())
    monkeypatch.setattr(context,'confidential_introspection_credentials',lambda:('fixture','secret'))
    monkeypatch.setattr(context,'introspect_access_token',AsyncMock(return_value={'active':True,'sub':'subject','client_id':'controlplane-frontend'}))
    respx.post('https://user-owner.test/api/v1/internal/identity/session-member').mock(return_value=httpx.Response(200,content=json.dumps(body),headers={'content-type':'application/json'}))
    request=Request({'type':'http','headers':[(b'authorization',b'Bearer tenant'),(b'x-tenant-id',tenant.encode()),(b'x-auth-session-token',b'browser')]})
    reply=await (context.verification_context(request) if endpoint=='verification' else context.connect_session_context(request))
    assert reply.status_code==(403 if body is None else 503)
    assert reply.headers['cache-control']=='no-store' and reply.headers['pragma']=='no-cache'
    assert (json.loads(reply.body).get('code')=='membership_revoked')==(body is None)


@pytest.mark.parametrize('status',[401,403,307,500,503])
@respx.mock
async def test_failed_or_redirected_owner_is_not_revocation(owner,status):
    respx.post('https://user-owner.test/api/v1/internal/identity/session-member').mock(return_value=httpx.Response(status,headers={'location':'https://other.test'},text='private detail'))
    with pytest.raises(context.SessionUnavailable):
        await context.current_member(uuid.uuid4(),'subject')


@respx.mock
async def test_unreachable_owner_cannot_use_a_cached_member(owner):
    peer=respx.post('https://user-owner.test/api/v1/internal/identity/session-member')
    peer.mock(return_value=httpx.Response(200,json={'user_id':str(uuid.uuid4())}))
    tenant=uuid.uuid4()
    await context.current_member(tenant,'subject')
    peer.mock(side_effect=httpx.ConnectError('offline'))
    with pytest.raises(context.SessionUnavailable):
        await context.current_member(tenant,'subject')
    assert peer.call_count==2
