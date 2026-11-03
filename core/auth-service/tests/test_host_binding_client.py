"""Owner RPC identity binding and fail-closed reconciliation; no product imports."""
import json
import uuid

import httpx
import pytest
from fastapi import HTTPException
from auth_service.host_binding_client import HttpHostBindingClient


@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['good', 'tenant', 'subject', 'organization', 'http', 'json'])
async def test_owner_client_binds_response_and_suppresses_provider_details(mode):
    tenant, org = uuid.uuid4(), uuid.uuid4()
    def handler(request):
        assert json.loads(request.content) == {'tenant_id': str(tenant), 'subject': 'verified-subject'}
        data = {'tenant_id': str(tenant), 'subject': 'verified-subject', 'organization_id': str(org)}
        if mode == 'http': return httpx.Response(503, text='private provider diagnostic')
        if mode == 'json': return httpx.Response(200, text='private provider diagnostic')
        if mode == 'tenant': data['tenant_id'] = str(uuid.uuid4())
        if mode == 'subject': data['subject'] = 'another-subject'
        if mode == 'organization': data['organization_id'] = 'invalid'
        return httpx.Response(200, json=data)
    client = HttpHostBindingClient('https://owner.test', 'x' * 48, httpx.MockTransport(handler))
    if mode == 'good':
        assert await client.resolve(tenant, 'verified-subject') == org
    else:
        with pytest.raises(HTTPException) as failure:
            await client.resolve(tenant, 'verified-subject')
        assert failure.value.status_code == 503
        assert 'private' not in failure.value.detail


@pytest.mark.asyncio
@pytest.mark.parametrize('url,token', [('', 'x' * 48), ('https://owner.test', '')])
async def test_owner_not_configured_has_no_local_persistence_fallback(url, token):
    client = HttpHostBindingClient(url, token, httpx.MockTransport(lambda r: pytest.fail('unexpected HTTP')))
    with pytest.raises(HTTPException) as failure:
        await client.resolve(uuid.uuid4(), 'verified-subject')
    assert failure.value.status_code == 503
