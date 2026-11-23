"""Synthetic owner grants; no deployed accounts or grants are modified."""
import json
import time
import uuid

import httpx
import jwt
import pytest
import respx

from auth_service import deps, transfer_permission as permission
from auth_service.schemas import AuthMeResponse
from auth_service.scoped_session import ScopeGrant
from controlplane_api.config import settings
from controlplane_api.exceptions import UnauthorizedException
from test_scoped_session import scoped_owner


@pytest.fixture
def transfer_grant(tmp_path, monkeypatch, scoped_owner):
    g = scoped_owner
    row = dict(id='synthetic-transfer', issuer='https://issuer.invalid/realm',
               subject=g['subject'], client='controlplane-frontend',
               tenant=g['tenant_id'], organization=g['organization_id'],
               scopeGeneration=g['generation'], scopeManifest=g['manifest_sha256'],
               expiresAt=int(time.time()) + 1800, capability=permission.CAPABILITY)
    path = tmp_path / 'grants.json'
    def save(rows):
        path.write_text(json.dumps({'version': 1, 'grants': rows}))
        path.chmod(0o600)
    save([row])
    monkeypatch.setenv('AUTH_TRANSFER_GRANTS_FILE', str(path))
    return row, save, path


async def issue(app, http_client, g, row, requested=True):
    async def claims():
        return {'sub': g['subject'], 'iss': row['issuer'], 'azp': row['client'],
                'scope': 'openid '+permission.CAPABILITY}
    app.dependency_overrides[deps.get_access_token_claims] = claims
    try:
        return await http_client.post('/auth/scoped-session',
            headers={'Authorization': 'Bearer synthetic-provider'},
            json={'tenant_id': g['tenant_id'], 'organization_id': g['organization_id'],
                  'identity_transfer': requested})
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims, None)


@respx.mock
async def test_actual_issued_token_reaches_current_user_and_revocation_refuses(
        app, http_client, scoped_owner, transfer_grant):
    row, save, _ = transfer_grant
    peer = respx.post('https://scope.local/api/v1/internal/organization-authority/check')
    peer.mock(return_value=httpx.Response(200, json=scoped_owner))
    response = await issue(app, http_client, scoped_owner, row)
    assert response.status_code == 200, response.text
    token = response.json()['access_token']
    # Signature, issuer, expiry and native current-user conversion all run.
    claims = await deps.get_access_token_claims(token)
    user = await deps.get_current_user(claims)
    assert permission.CAPABILITY in user.scopes
    assert user.sub == scoped_owner['subject']
    assert await deps.get_current_tenant(claims) == uuid.UUID(row['tenant'])
    assert claims['permissions'] == []
    save([])
    with pytest.raises(UnauthorizedException):
        await deps.get_access_token_claims(token)


@respx.mock
async def test_membership_without_explicit_intent_does_not_copy_provider_scope(
        app, http_client, scoped_owner, transfer_grant):
    row, _, _ = transfer_grant
    respx.post('https://scope.local/api/v1/internal/organization-authority/check').mock(
        return_value=httpx.Response(200, json=scoped_owner))
    response = await issue(app, http_client, scoped_owner, row, False)
    assert response.status_code == 200
    claims = jwt.decode(response.json()['access_token'], settings.usable_api_key_exchange_secret(),
                        algorithms=['HS256'], issuer='https://spanopticon.internal/tenant-session')
    assert permission.CAPABILITY not in AuthMeResponse.from_claims(claims).scopes
    assert permission.CLAIM not in claims


@pytest.mark.parametrize('field', ['subject','client','tenant','organization','issuer',
                                   'scopeGeneration','scopeManifest','expiresAt'])
@respx.mock
async def test_foreign_stale_or_expired_grant_cannot_issue(
        app, http_client, scoped_owner, transfer_grant, field):
    row, save, _ = transfer_grant
    changed = dict(row)
    changed[field] = (int(time.time())-1 if field == 'expiresAt' else
                      str(uuid.uuid4()) if field in ('tenant','organization') else
                      'b'*64 if field == 'scopeManifest' else 'foreign')
    save([changed])
    respx.post('https://scope.local/api/v1/internal/organization-authority/check').mock(
        return_value=httpx.Response(200, json=scoped_owner))
    assert (await issue(app, http_client, scoped_owner, row)).status_code == 403


@pytest.mark.parametrize('change', ['revoked','generation','network','unavailable'])
@respx.mock
async def test_token_use_rechecks_membership_and_generation(
        app, http_client, scoped_owner, transfer_grant, change):
    row, _, _ = transfer_grant
    peer = respx.post('https://scope.local/api/v1/internal/organization-authority/check')
    peer.mock(return_value=httpx.Response(200, json=scoped_owner))
    response = await issue(app, http_client, scoped_owner, row)
    assert response.status_code == 200
    if change == 'unavailable':
        peer.mock(return_value=httpx.Response(503))
    else:
        body = None if change == 'revoked' else {**scoped_owner,
            ('network_id' if change == 'network' else 'generation'): 'changed'}
        peer.mock(return_value=httpx.Response(200, json=body))
    with pytest.raises(UnauthorizedException):
        await deps.get_access_token_claims(response.json()['access_token'])


@pytest.mark.parametrize('change', ['mode','symlink','duplicate','ambiguous','unknown','expired','absent'])
def test_invalid_or_missing_configuration_refuses(transfer_grant, scoped_owner, monkeypatch, change):
    row, save, path = transfer_grant
    if change == 'mode': path.chmod(0o644)
    elif change == 'symlink':
        target = path.with_name('target.json'); path.rename(target); path.symlink_to(target)
    elif change == 'duplicate': save([row,row])
    elif change == 'ambiguous': save([row,{**row,'id':'other'}])
    elif change == 'unknown': save([{**row,'hidden':True}])
    elif change == 'expired': save([{**row,'expiresAt':1}])
    elif change == 'absent': monkeypatch.delenv('AUTH_TRANSFER_GRANTS_FILE')
    with pytest.raises((ValueError,OSError)):
        permission.select({'iss':row['issuer'],'sub':row['subject'],'azp':row['client']},
                          ScopeGrant.model_validate(scoped_owner))


async def test_provider_scope_is_not_a_grant():
    claims = await permission.validate({'scope':'openid '+permission.CAPABILITY,
                                        'sub':'person','iss':'https://issuer.invalid'})
    assert claims['scope'] == 'openid'


@pytest.mark.parametrize('change', ['tenant','organization','subject','client','marker','expiry'])
@respx.mock
async def test_signed_source_tenant_or_changed_marker_is_refused(
        app,http_client,scoped_owner,transfer_grant,change):
    row, _, _ = transfer_grant
    respx.post('https://scope.local/api/v1/internal/organization-authority/check').mock(
        return_value=httpx.Response(200,json=scoped_owner))
    response = await issue(app,http_client,scoped_owner,row)
    assert response.status_code == 200
    claims = jwt.decode(response.json()['access_token'],settings.usable_api_key_exchange_secret(),
                        algorithms=['HS256'],issuer='https://spanopticon.internal/tenant-session')
    key = {'tenant':'tenant_id','organization':'organization_id','subject':'sub','client':'azp',
           'marker':permission.CLAIM,'expiry':'exp'}[change]
    claims[key] = (str(uuid.uuid4()) if change in ('tenant','organization') else
                   {} if change == 'marker' else row['expiresAt']+1 if change == 'expiry' else 'foreign')
    token = jwt.encode(claims,settings.usable_api_key_exchange_secret(),algorithm='HS256')
    with pytest.raises(UnauthorizedException):
        await deps.get_access_token_claims(token)

@pytest.mark.parametrize('raw', [
    '{"version":1,"version":1,"grants":[]}',
    '{"version":true,"grants":[]}',
    '{"version":1,"grants":NaN}',
    '{"version":1,"grants":{}}',
    'x'*65537,
])
def test_malformed_file_refuses(transfer_grant,raw):
    _,_,path=transfer_grant
    path.write_text(raw)
    with pytest.raises(ValueError):
        permission.configuration()


async def test_unrelated_claims_keep_existing_shape():
    claims={'sub':'ordinary','permissions':['read']}
    assert await permission.validate(claims) is claims


@respx.mock
async def test_changed_grant_hash_and_shorter_expiry_refuse_existing_token(
        app,http_client,scoped_owner,transfer_grant):
    row,save,_=transfer_grant
    respx.post('https://scope.local/api/v1/internal/organization-authority/check').mock(
        return_value=httpx.Response(200,json=scoped_owner))
    save([{**row,'expiresAt':int(time.time())+100}])
    response=await issue(app,http_client,scoped_owner,row)
    assert response.status_code==200
    claims=await deps.get_access_token_claims(response.json()['access_token'])
    assert claims['exp']<=int(time.time())+100
    save([row])
    with pytest.raises(UnauthorizedException):
        await deps.get_access_token_claims(response.json()['access_token'])


@pytest.mark.asyncio
async def test_portal_media_requires_current_run_and_owner_grant(transfer_grant, monkeypatch):
    from controlplane_identity.nightly import admitted_run
    from types import SimpleNamespace
    from auth_service import scoped_session

    row, save, _ = transfer_grant
    row.update(subject=permission.PORTAL_SUBJECT, tenant=permission.PORTAL_TENANT,
               issuer=permission.PORTAL_ISSUER, portalMedia=True)
    save([row])
    org = SimpleNamespace(tenant_id=uuid.UUID(row['tenant']), organization_id=uuid.UUID(row['organization']),
                          generation=row['scopeGeneration'], manifest_sha256=row['scopeManifest'], network_id='hyperme.sh')
    binding = dict(version=1, run='123-1-portal-device-transfer', generation='c'*64,
        operation='33333333-3333-4333-8333-333333333333', scope=dict(
        suite='portal-device-transfer', realm='controlplane', issuer=row['issuer'], subject=row['subject'],
        tenant=row['tenant'], organization=row['organization'], clients=[row['client']],
        origins=['https://portal.test.hyperme.sh']))
    claims = dict(sub=row['subject'], iss=row['issuer'], azp=row['client'],
                  nightly_run={k: binding[k] for k in ('run', 'generation')})
    with pytest.raises(ValueError):
        permission.select(claims, org)
    with admitted_run(binding):
        selected = permission.select(claims, org)
        payload = claims | dict(iss='https://spanopticon.internal/tenant-session', scope='openid',
            spanopticon_auth='tenant_session', scope_kind='organization', scope_version=1,
            tenant_id=row['tenant'], organization_id=row['organization'], network_id=org.network_id,
            scope_generation=org.generation, scope_manifest_sha256=org.manifest_sha256, exp=row['expiresAt'])
        permission.attach(payload, selected)
        async def current(*_):
            return org
        monkeypatch.setattr(scoped_session, 'current_scope', current)
        assert set(permission.MEDIA) <= set((await permission.validate(payload))['scope'].split())
        with pytest.raises(ValueError):
            await permission.validate(payload | {'scope': 'openid ' + permission.CAPABILITY})
        with pytest.raises(ValueError):
            permission.select(claims | {'nightly_run': {'run': 'expired', 'generation': 'd'*64}}, org)
        save([])
        with pytest.raises(ValueError):
            await permission.validate(payload)
    with admitted_run(binding | {'run': '123-1-s3rch-device-transfer', 'scope': binding['scope'] | {'suite': 's3rch-device-transfer'}}):
        save([row])
        with pytest.raises(ValueError):
            permission.select(claims, org)


@pytest.mark.asyncio
async def test_only_explicit_media_authority_survives_provider_claims():
    scopes = 'openid ' + ' '.join(permission.MEDIA)
    assert (await permission.validate({'scope': scopes}))['scope'] == 'openid'
    api_key = {'scope': scopes, 'spanopticon_auth': 'api_key'}
    assert await permission.validate(api_key) == api_key
