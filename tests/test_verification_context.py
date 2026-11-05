import json
import time
import uuid
from unittest.mock import AsyncMock
import pytest
from starlette.requests import Request
from auth_service import connect_session as session

@pytest.mark.asyncio
async def test_context_requires_both_tokens_and_live_membership(monkeypatch):
    tenant=str(uuid.uuid4()); member=str(uuid.uuid4()); now=int(time.time())
    tenant_claims={'tenant_id':tenant,'sub':'subject','spanopticon_auth':'tenant_session','azp':'controlplane-frontend'}
    origin={'iss':session.settings.keycloak_issuer.rstrip('/'),'sub':'subject','azp':'controlplane-frontend','sid':'sid','exp':now+300,'iat':now,'auth_time':now,
            'email':'owner@example.test','email_verified':True,'identity_provider':'google'}
    monkeypatch.setattr(session,'try_decode_tenant_session_jwt',lambda token:tenant_claims)
    monkeypatch.setattr(session,'get_keycloak_jwt_validator',lambda:type('Validator',(),{'validate':AsyncMock(return_value=origin)})())
    monkeypatch.setattr(session,'confidential_introspection_credentials',lambda:('service','secret'))
    monkeypatch.setattr(session,'introspect_access_token',AsyncMock(return_value={'active':True,'sub':'subject','client_id':'controlplane-frontend'}))
    membership=AsyncMock(return_value=member);monkeypatch.setattr(session,'current_member',membership)
    monkeypatch.setenv('AUTH_VERIFICATION_EMAIL_ISSUER',origin['iss']);monkeypatch.setenv('AUTH_VERIFICATION_EMAIL_PROVIDERS','google')
    request=Request({'type':'http','headers':[(b'authorization',b'Bearer tenant-token'),(b'x-tenant-id',tenant.encode()),(b'x-auth-session-token',b'original-token')]})
    response=await session.verification_context(request)
    assert response.status_code==200
    facts=json.loads(response.body)
    assert facts['source']=='auth_verification_v1' and facts['member_id']==member
    membership.assert_awaited_once()
    monkeypatch.setattr(session,'current_member',AsyncMock(side_effect=session.MembershipRevoked()))
    assert (await session.verification_context(request)).status_code==403
    assert (await session.verification_context(Request({'type':'http','headers':[]}))).status_code==403
