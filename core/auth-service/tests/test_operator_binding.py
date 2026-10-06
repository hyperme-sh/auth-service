import uuid
import pytest
from auth_service import operator_binding as binding

TENANT = 'e96a5fc3-ef21-4990-8381-7206c5f6de9f'
OBJECT = '21dc06a7-b56b-4b1c-bd23-46e1394cf9a7'

@pytest.fixture
def identity(monkeypatch):
    monkeypatch.setattr(binding.settings, 'keycloak_issuer', binding.PRODUCTION_ISSUER)
    monkeypatch.setenv('PANOPTICON_OPERATOR_ENTRA_TENANT_ID', TENANT)
    monkeypatch.setenv('PANOPTICON_OPERATOR_ENTRA_OBJECT_ID', OBJECT)
    return dict(iss=binding.PRODUCTION_ISSUER, sub='kc-user', email='chris@fyberlabs.com',
                login_provider='microsoft', entra_tenant_id=TENANT, entra_object_id=OBJECT)

def test_exact_identity_grants_only_in_marketplace(identity):
    assert binding.eligible(identity, binding.MARKETPLACE_TENANT_ID)
    assert not binding.eligible(identity, uuid.uuid4())
    assert binding.eligible({**identity, 'email':'renamed@fyberlabs.com'}, binding.MARKETPLACE_TENANT_ID)
    assert 'operator:program' in binding.permissions(identity, binding.MARKETPLACE_TENANT_ID, binding.ROLE, [])
    assert 'operator:console' in binding.permissions(identity, binding.MARKETPLACE_TENANT_ID, 'renter', [])

@pytest.mark.parametrize('key,value', [('entra_tenant_id',str(uuid.uuid4())),
    ('entra_object_id',str(uuid.uuid4())), ('entra_object_id',None),
    ('login_provider','google'), ('login_provider',None),
    ('iss','https://auth.test.hyperme.sh/realms/controlplane'),
    ('purpose','host-setup'), ('panopticon_auth','tenant_session')])
def test_wrong_identity_cannot_reuse_role_or_mapped_permissions(identity,key,value):
    claims = {**identity,key:value}
    assert not binding.eligible(claims,binding.MARKETPLACE_TENANT_ID)
    assert binding.permissions(claims,binding.MARKETPLACE_TENANT_ID,binding.ROLE,
                               ['operator:console','operator:program','org:own']) == ['org:own']

def test_missing_config_disables_access(identity,monkeypatch):
    monkeypatch.delenv('PANOPTICON_OPERATOR_ENTRA_OBJECT_ID')
    assert not binding.eligible(identity,binding.MARKETPLACE_TENANT_ID)

def test_persistent_attributes_are_not_identity_proof(identity):
    claims={k:v for k,v in identity.items() if not k.startswith('entra_')}
    claims.update(idp_provider='microsoft',idp_org=TENANT,idp_oid=OBJECT)
    assert not binding.eligible(claims,binding.MARKETPLACE_TENANT_ID)

@pytest.mark.asyncio
@pytest.mark.parametrize('provider,allowed', [('microsoft',True),('google',False),(None,False)])
async def test_switch_filters_all_operator_sources(identity,provider,allowed,app,http_client,monkeypatch):
    monkeypatch.setattr(binding.settings, 'keycloak_issuer', binding.PRODUCTION_ISSUER)
    from auth_service import deps
    from auth_service.tenant_switch import TenantSwitchGrant
    from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt
    async def claims():
        return {**identity,'login_provider':provider,'permissions':['operator:resolve']}
    async def provision(*args,**kwargs):
        pass
    async def grant(*args,**kwargs):
        return TenantSwitchGrant(role_name=binding.ROLE,permissions=('operator:console','user:view_only'))
    monkeypatch.setattr(binding,'provision',provision)
    monkeypatch.setattr('auth_service.routes.authorize_tenant_switch',grant)
    app.dependency_overrides[deps.get_access_token_claims]=claims
    try:
        response=await http_client.post('/auth/switch-tenant',headers={'Authorization':'Bearer fake.jwt'},
                                       json={'tenant_id':str(binding.MARKETPLACE_TENANT_ID)})
        assert response.status_code==200,response.text
        permissions=try_decode_tenant_session_jwt(response.json()['access_token'])['permissions']
        assert ('operator:console' in permissions) is allowed
        assert ('operator:resolve' in permissions) is allowed
        assert 'user:view_only' in permissions
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims,None)
