"""Mint only owner-authorized, generation-bound organization sessions."""
import os
import uuid
from urllib.parse import urlsplit

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from auth_service.deps import CurrentAuthUser, get_access_token_claims
from auth_service import startup_identity
from auth_service._startup_contract import fingerprint
from controlplane_api.config import settings
from api.infrastructure.security.tenant_session_jwt import mint_tenant_session_jwt, is_smoke_session

router=APIRouter()


class ScopeUnavailable(RuntimeError):pass


class ScopedRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    tenant_id: uuid.UUID
    organization_id: uuid.UUID
    identity_transfer: StrictBool = False


class ScopeGrant(BaseModel):
    model_config=ConfigDict(extra='forbid')
    subject: str
    user_id: uuid.UUID
    network_id: str=Field(min_length=1,max_length=256)
    tenant_id: uuid.UUID
    organization_id: uuid.UUID
    role: str=Field(pattern='^(admin|member)$')
    can_purchase: StrictBool
    generation: str=Field(min_length=1,max_length=256)
    manifest_sha256: str=Field(pattern='^[a-f0-9]{64}$')


def owner_configuration():
    url=os.environ.get('AUTH_SCOPE_AUTHORITY_URL','').rstrip('/')
    token=os.environ.get('AUTH_SCOPE_AUTHORITY_TOKEN','')
    generation=os.environ.get('AUTH_SCOPE_GENERATION','')
    manifest=os.environ.get('AUTH_SCOPE_MANIFEST_SHA256','')
    if os.environ.get('STARTUP_IDENTITY_ENABLED') == '1' and not generation and not manifest:
        config = startup_identity.configuration()
        if config['binding']['version'] == 1:
            generation, manifest = 'startup-v1', fingerprint(config)
    if not all((url,token,generation,manifest)):raise ScopeUnavailable('Scope owner configuration required')
    try:
        parsed=urlsplit(url)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError('Verified TLS owner endpoint required')
    except ValueError as exc:
        raise ScopeUnavailable('Verified TLS owner endpoint required') from exc
    return url,token,generation,manifest


async def current_scope(subject, tenant_id, organization_id):
    try:
        config = None
        if os.environ.get('STARTUP_IDENTITY_ENABLED') == '1':
            config = startup_identity.configuration()
        if config and config['binding']['version'] == 2 and (
                str(tenant_id) == config['owner']['tenant_id']
                or subject == config['binding']['oidc']['broker_subject']):
            binding = config['binding']
            if (str(tenant_id) != config['owner']['tenant_id'] or subject != binding['oidc']['broker_subject']
                    or str(organization_id) not in {row['organization_id'] for row in binding['organizations'].values()}):
                return None
            body = await startup_identity.owner(
                'scope', config, subject=subject, tenant_id=str(tenant_id), organization_id=str(organization_id))
            generation, manifest = 'startup-v1', fingerprint(config)
            if body is not None and (not isinstance(body, dict) or body.get('user_id') != subject
                                     or body.get('network_id') != config['owner']['network_id']):
                raise ValueError('Startup organization authority binding differs')
        else:
            url, token, generation, manifest = owner_configuration()
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                response = await client.post(
                    url + '/api/v1/internal/organization-authority/check',
                    headers={'Authorization': 'Bearer ' + token},
                    json={'subject': subject, 'tenant_id': str(tenant_id),
                          'organization_id': str(organization_id), 'capability': 'member'},
                )
                response.raise_for_status()
                body = response.json()
            if config and config['binding']['version'] == 1 and isinstance(body, dict) and body.get('generation') == 'startup-v1':
                generation, manifest = 'startup-v1', fingerprint(config)
        if body is None:
            return None
        grant = ScopeGrant.model_validate(body)
        if (grant.subject != subject or grant.tenant_id != tenant_id or grant.organization_id != organization_id
                or grant.generation != generation or grant.manifest_sha256 != manifest):
            raise ValueError('Scope binding differs')
        return grant
    except (httpx.HTTPError, OSError, ValueError) as exc:
        raise ScopeUnavailable('Current scope authority unavailable') from exc


@router.post('/scoped-session')
async def scoped_session(body: ScopedRequest,request: Request,user: CurrentAuthUser,claims: dict=Depends(get_access_token_claims)):
    headers={'Cache-Control':'no-store','Pragma':'no-cache'}
    if is_smoke_session(claims) or claims.get('spanopticon_auth'):
        raise HTTPException(403,'Fresh issuer identity required',headers=headers)
    client_id=claims.get('azp') or claims.get('client_id')
    if (not isinstance(client_id,str) or not client_id.strip()
            or (claims.get('azp') and claims.get('client_id') and claims['azp']!=claims['client_id'])):
        raise HTTPException(403,'Unambiguous verified issuer client required',headers=headers)
    selected=request.headers.get('X-Tenant-ID')
    if selected and selected!=str(body.tenant_id):raise HTTPException(403,'Tenant selection differs',headers=headers)
    from controlplane_identity.nightly import current_binding
    binding = current_binding()
    if binding is not None and (user.sub != binding['scope']['subject'] or str(body.tenant_id) != binding['scope']['tenant']
                                or str(body.organization_id) != binding['scope']['organization']):
        raise HTTPException(403, 'Nightly scope differs', headers=headers)
    try:grant=await current_scope(user.sub,body.tenant_id,body.organization_id)
    except ScopeUnavailable as exc:raise HTTPException(503,'Scope authority unavailable',headers=headers) from exc
    if grant is None:raise HTTPException(403,'Current organization membership required',headers=headers)
    from auth_service import transfer_permission
    try:
        transfer = transfer_permission.select(claims, grant) if body.identity_transfer else None
    except (ValueError, OSError):
        raise HTTPException(403, 'Transfer permission unavailable', headers=headers) from None
    base=mint_tenant_session_jwt(claims={**transfer_permission.without_transfer(claims),'azp':client_id,'permissions':[],'realm_access':{'roles':[]},'groups':[]},tenant_id=body.tenant_id,extra_roles=['org:'+grant.role])
    payload=jwt.decode(base,settings.usable_api_key_exchange_secret(),algorithms=['HS256'],issuer='https://spanopticon.internal/tenant-session')
    payload.update(scope_version=1,scope_kind='organization',organization_id=str(grant.organization_id),network_id=grant.network_id,
        scope_generation=grant.generation,scope_manifest_sha256=grant.manifest_sha256)
    if transfer is not None:
        transfer_permission.attach(payload, transfer)
    access=jwt.encode(payload,settings.usable_api_key_exchange_secret(),algorithm='HS256')
    from auth_service import outbox
    from controlplane_api.event_types import AUTH_TOKEN_ISSUED_V1
    await outbox.publish_auth_event(token=access,tenant_id=body.tenant_id,event_type=AUTH_TOKEN_ISSUED_V1,
        payload={'subject':user.sub,'grant_type':'organization_scope','client_id':client_id,
                 'organization_id':str(grant.organization_id),'network_id':grant.network_id,
                 'scope_generation':grant.generation,'scope_manifest_sha256':grant.manifest_sha256})
    from fastapi.responses import JSONResponse
    return JSONResponse({'access_token':access,'expires_in':payload['exp']-payload['iat'],'token_type':'Bearer'},headers=headers)
