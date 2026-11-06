"""Boundary regressions adopted from hyperme-sh/auth-service PR #1."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from auth_service import routes, deps
from user_service import identity_tenant_switch as tenant_switch
from auth_service.schemas import AuthMeResponse, EnrollmentGrantRequest
from test_switch_tenant import _FakeSession
from controlplane_identity.security.tenant_session_jwt import try_decode_tenant_session_jwt

@pytest.mark.asyncio
@pytest.mark.parametrize('platform',[False, True])
async def test_email_collision_rejects_other_subject(platform):
    row=SimpleNamespace(keycloak_sub='other-subject')
    assert await tenant_switch._user_by_email_or_sub(_FakeSession([row]), email='same@example.com',sub='caller', platform=platform,tenant_id=uuid.uuid4()) is None

@pytest.mark.asyncio
async def test_disabled_platform_account_has_no_grant():
    tid=uuid.uuid4()
    row=SimpleNamespace(keycloak_sub='caller',is_active=False)
    with patch.object(tenant_switch,'set_current_tenant_id_guc',new=AsyncMock()):
        assert await tenant_switch.authorize_tenant_switch(AuthMeResponse(sub='caller',email='a@example.com'),tid,session=_FakeSession([tid,None,None,row])) is None

@pytest.mark.asyncio
async def test_switch_drops_source_tenant_permissions_and_roles(app,http_client,tenant_uuid):
    async def claims():
        return {'sub':'caller','email':'caller@example.com','spanopticon_auth':'tenant_session','tenant_id':str(uuid.uuid4()),'permissions':['full:access','host:manage_tenants'],'realm_access':{'roles':['admin']},'groups':['renter', 'host']}
    app.dependency_overrides[deps.get_access_token_claims]=claims
    try:
        with patch.object(routes,'authorize_tenant_switch',new=AsyncMock(return_value=tenant_switch.TenantSwitchGrant(role_name='guest',permissions=('user:view_only',)))):
            response=await http_client.post('/auth/switch-tenant',headers={'Authorization':'Bearer fake'},json={'tenant_id':str(tenant_uuid)})
        assert response.status_code==200,response.text
        payload=try_decode_tenant_session_jwt(response.json()['access_token'])
        assert 'full:access' not in payload['permissions']
        assert 'host:manage_tenants' not in payload['permissions']
        assert 'user:view_only' in payload['permissions']
        assert 'admin' not in payload['realm_access']['roles']
        assert payload['groups'] == []
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims,None)

@pytest.mark.asyncio
@pytest.mark.parametrize('header',[False,True])
async def test_public_enrollment_rejects_foreign_tenant_before_write(header,monkeypatch):
    tid=uuid.uuid4()
    grant=AsyncMock()
    monkeypatch.setattr(routes,'grant_held_roles',grant)
    request=Request({'type':'http','headers':[(b'x-tenant-id',str(tid).encode())] if header else []})
    with pytest.raises(HTTPException) as error:
        await routes.auth_enrollment_grant(EnrollmentGrantRequest(tenant_id=tid,held_roles=['renter']),request,AuthMeResponse(sub='caller'),AsyncMock())
    assert error.value.status_code==403
    grant.assert_not_awaited()

@pytest.mark.asyncio
async def test_marketplace_enrollment_remains_available(monkeypatch):
    from controlplane_tenancy.marketplace import MARKETPLACE_TENANT_ID
    from auth_service.enrollment import EnrollmentGrantResult
    grant=AsyncMock(return_value=EnrollmentGrantResult(granted=('renter',),refused=(),wallet_address=None))
    monkeypatch.setattr(routes,'grant_held_roles',grant)
    response=await routes.auth_enrollment_grant(EnrollmentGrantRequest(tenant_id=MARKETPLACE_TENANT_ID,held_roles=['renter']),Request({'type':'http','headers':[]}),AuthMeResponse(sub='caller'),AsyncMock())
    assert response.granted == ['renter'] or response.granted == ('renter',)
    assert grant.await_args.kwargs['tenant_id']==MARKETPLACE_TENANT_ID

@pytest.mark.asyncio
@pytest.mark.parametrize('has_role_id', [False, True])
async def test_membership_without_resolved_role_cannot_switch(has_role_id):
    tid=uuid.uuid4()
    member=SimpleNamespace(keycloak_sub='caller',is_active=True,tenant_id=tid,
                           role_id=uuid.uuid4() if has_role_id else None)
    values=[tid,member]+([None] if has_role_id else [])
    with patch.object(tenant_switch,'set_current_tenant_id_guc',new=AsyncMock()):
        grant=await tenant_switch.authorize_tenant_switch(
            AuthMeResponse(sub='caller',email='caller@example.com'),tid,
            session=_FakeSession(values))
    assert grant is None

@pytest.mark.parametrize('scope', ['foreign', 'unscoped', 'marketplace'])
@pytest.mark.parametrize('role', ['admin', 'org_admin'])
def test_org_admin_enrollment_requires_target_tenant_authority(scope, role):
    from auth_service.enrollment import held_roles_from_identity
    from controlplane_tenancy.marketplace import MARKETPLACE_TENANT_ID
    tenant_id = {'foreign': uuid.uuid4(), 'unscoped': None,
                 'marketplace': MARKETPLACE_TENANT_ID}[scope]
    user = AuthMeResponse(sub='caller', tenant_id=tenant_id, roles=[role])
    granted, refused = held_roles_from_identity(user, ['org_admin'])
    assert ('org_admin' in granted) == (scope == 'marketplace')
    assert ('org_admin' in refused) == (scope != 'marketplace')

@pytest.mark.asyncio
async def test_foreign_admin_enrollment_does_not_write_membership(monkeypatch):
    from user_service import identity_enrollment as enrollment
    from controlplane_tenancy.marketplace import MARKETPLACE_TENANT_ID
    monkeypatch.setattr(enrollment, '_bound_wallet', AsyncMock(return_value=None))
    monkeypatch.setattr(enrollment, '_get_or_create_role', AsyncMock())
    monkeypatch.setattr(enrollment, '_require_tenant', AsyncMock())
    monkeypatch.setattr(enrollment, 'set_current_tenant_id_guc', AsyncMock())
    member = AsyncMock()
    monkeypatch.setattr(enrollment, '_ensure_membership_user', member)
    result = await enrollment.grant_held_roles(
        AsyncMock(), AuthMeResponse(sub='caller', tenant_id=uuid.uuid4(), roles=['admin']),
        tenant_id=MARKETPLACE_TENANT_ID, requested=['org_admin'])
    assert result.granted == ()
    assert result.refused == ('org_admin',)
    member.assert_not_awaited()
