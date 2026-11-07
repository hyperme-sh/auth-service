"""Only current, well-formed user-owner grants may authorize setup tokens."""
import json
import uuid

from fastapi import HTTPException
import httpx
import pytest
import respx

from auth_service.host_setup import authorize_host_setup


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_URL','https://user-owner.test')
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_TOKEN','fixture-owner-credential')


@respx.mock
async def test_only_subject_and_target_cross_authority_boundary(owner):
    member, tenant = uuid.uuid4(),uuid.uuid4()
    rpc=respx.post('https://user-owner.test/api/v1/internal/identity/host-setup').mock(return_value=httpx.Response(200,json={'user_id':str(member)}))
    grant=await authorize_host_setup('opaque:subject',tenant)
    assert grant.user_id==member
    request=rpc.calls.last.request
    assert json.loads(request.content)=={'subject':'opaque:subject','tenant_id':str(tenant)}
    assert request.headers['authorization']=='Bearer fixture-owner-credential'
    assert 'x-api-key' not in request.headers


@respx.mock
async def test_durable_owner_denial_has_no_grant(owner):
    respx.post('https://user-owner.test/api/v1/internal/identity/host-setup').mock(return_value=httpx.Response(200,content=b'null',headers={'content-type':'application/json'}))
    assert await authorize_host_setup('opaque:subject',uuid.uuid4()) is None


@pytest.mark.parametrize('body',[{},[],False,{'user_id':'bad'}, {'user_id':str(uuid.uuid4()),'permissions':['full:access']}])
@respx.mock
async def test_malformed_owner_success_is_unavailable_not_authority(owner,body):
    respx.post('https://user-owner.test/api/v1/internal/identity/host-setup').mock(return_value=httpx.Response(200,json=body))
    with pytest.raises(HTTPException) as error:
        await authorize_host_setup('opaque:subject',uuid.uuid4())
    assert error.value.status_code==503


@pytest.mark.parametrize('status',[401,403,500,503,307])
@respx.mock
async def test_failed_or_redirected_owner_never_authorizes(owner,status):
    respx.post('https://user-owner.test/api/v1/internal/identity/host-setup').mock(return_value=httpx.Response(status,headers={'location':'https://untrusted.test'},text='private upstream detail'))
    with pytest.raises(HTTPException) as error:
        await authorize_host_setup('opaque:subject',uuid.uuid4())
    assert error.value.status_code==503
    assert 'private' not in str(error.value.detail)


@respx.mock
async def test_owner_network_failure_has_no_cached_grant(owner):
    rpc=respx.post('https://user-owner.test/api/v1/internal/identity/host-setup').mock(side_effect=httpx.ConnectError('private failure'))
    with pytest.raises(HTTPException) as error:
        await authorize_host_setup('opaque:subject',uuid.uuid4())
    assert error.value.status_code==503 and rpc.call_count==1
