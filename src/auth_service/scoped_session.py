"""Mint only owner-authorized, generation-bound organization sessions."""
import os
import uuid

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from auth_service.deps import CurrentAuthUser, get_access_token_claims
from controlplane_api.config import settings
from api.infrastructure.security.tenant_session_jwt import mint_tenant_session_jwt, is_smoke_session

router=APIRouter()


class ScopeUnavailable(RuntimeError):pass


class ScopedRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    tenant_id: uuid.UUID
    organization_id: uuid.UUID


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


async def current_scope(subject,tenant_id,organization_id):
    url=os.environ.get('AUTH_SCOPE_AUTHORITY_URL','').rstrip('/')
    token=os.environ.get('AUTH_SCOPE_AUTHORITY_TOKEN','')
    generation=os.environ.get('AUTH_SCOPE_GENERATION','')
    manifest=os.environ.get('AUTH_SCOPE_MANIFEST_SHA256','')
    if not all((url,token,generation,manifest)):raise ScopeUnavailable('Scope owner configuration required')
    try:
        async with httpx.AsyncClient(timeout=10,follow_redirects=False) as client:
            r=await client.post(url+'/api/v1/internal/organization-authority/check',headers={'Authorization':'Bearer '+token},json={'subject':subject,'tenant_id':str(tenant_id),'organization_id':str(organization_id),'capability':'member'})
            r.raise_for_status();body=r.json()
        if body is None:return None
        grant=ScopeGrant.model_validate(body)
        if (grant.subject!=subject or grant.tenant_id!=tenant_id or grant.organization_id!=organization_id
                or grant.generation!=generation or grant.manifest_sha256!=manifest):
            raise ValueError('Scope binding differs')
        return grant
    except (httpx.HTTPError,ValueError) as exc:
        raise ScopeUnavailable('Current scope authority unavailable') from exc


@router.post('/scoped-session')
async def scoped_session(body: ScopedRequest,request: Request,user: CurrentAuthUser,claims: dict=Depends(get_access_token_claims)):
    headers={'Cache-Control':'no-store','Pragma':'no-cache'}
    if is_smoke_session(claims) or claims.get('spanopticon_auth'):
        raise HTTPException(403,'Fresh issuer identity required',headers=headers)
    selected=request.headers.get('X-Tenant-ID')
    if selected and selected!=str(body.tenant_id):raise HTTPException(403,'Tenant selection differs',headers=headers)
    try:grant=await current_scope(user.sub,body.tenant_id,body.organization_id)
    except ScopeUnavailable as exc:raise HTTPException(503,'Scope authority unavailable',headers=headers) from exc
    if grant is None:raise HTTPException(403,'Current organization membership required',headers=headers)
    base=mint_tenant_session_jwt(claims={**claims,'permissions':[],'realm_access':{'roles':[]},'groups':[]},tenant_id=body.tenant_id,extra_roles=['org:'+grant.role])
    payload=jwt.decode(base,settings.usable_api_key_exchange_secret(),algorithms=['HS256'],issuer='https://spanopticon.internal/tenant-session')
    payload.update(scope_version=1,organization_id=str(grant.organization_id),network_id=grant.network_id,
        scope_generation=grant.generation,scope_manifest_sha256=grant.manifest_sha256)
    access=jwt.encode(payload,settings.usable_api_key_exchange_secret(),algorithm='HS256')
    from api.infrastructure.messaging.tenant_event_publisher import get_tenant_event_publisher
    from controlplane_api.event_types import AUTH_TOKEN_ISSUED_V1
    await get_tenant_event_publisher().publish(tenant_id=body.tenant_id,event_type=AUTH_TOKEN_ISSUED_V1,
        payload={'subject':user.sub,'grant_type':'organization_scope','client_id':str(claims.get('azp') or settings.keycloak_client_id),
                 'organization_id':str(grant.organization_id),'network_id':grant.network_id,
                 'scope_generation':grant.generation,'scope_manifest_sha256':grant.manifest_sha256})
    from fastapi.responses import JSONResponse
    return JSONResponse({'access_token':access,'expires_in':payload['exp']-payload['iat'],'token_type':'Bearer'},headers=headers)
