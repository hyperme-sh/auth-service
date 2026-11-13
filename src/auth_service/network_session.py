"""Generation-bound network sessions from current User-owned authority only."""
import os
import uuid
from typing import Literal

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from auth_service.deps import CurrentAuthUser, get_access_token_claims
from auth_service.scoped_session import ScopeUnavailable
from controlplane_api.config import settings
from api.infrastructure.security.tenant_session_jwt import mint_tenant_session_jwt, is_smoke_session

router = APIRouter()


class NetworkRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    tenant_id: uuid.UUID


class NetworkGrant(BaseModel):
    model_config = ConfigDict(extra='forbid')
    subject: str
    user_id: uuid.UUID
    network_id: str = Field(min_length=1,max_length=256)
    tenant_id: uuid.UUID
    organization_id: None
    role: Literal['admin']
    can_purchase: Literal[False]
    generation: str = Field(min_length=1,max_length=256)
    manifest_sha256: str = Field(pattern='^[a-f0-9]{64}$')
    permissions: list[str]

    @field_validator('permissions')
    @classmethod
    def operator_only(cls, values):
        allowed={'operator:console','operator:support','operator:program','operator:resolve'}
        if len(values)!=len(set(values)) or not set(values)<=allowed:
            raise ValueError('Explicit network operator capabilities required')
        return values


async def current_network(subject, tenant_id):
    from auth_service.scoped_session import owner_configuration
    url,token,generation,manifest = owner_configuration()
    try:
        async with httpx.AsyncClient(timeout=10,follow_redirects=False) as client:
            response=await client.post(url+'/api/v1/internal/network-authority/check',headers={'Authorization':'Bearer '+token},json={'subject':subject,'tenant_id':str(tenant_id)})
            response.raise_for_status();body=response.json()
        if body is None:return None
        grant=NetworkGrant.model_validate(body)
        if (grant.subject!=subject or grant.tenant_id!=tenant_id or grant.generation!=generation
                or grant.manifest_sha256!=manifest or type(body.get('can_purchase')) is not bool):
            raise ValueError('Network authority binding differs')
        return grant
    except (httpx.HTTPError,ValueError) as exc:
        raise ScopeUnavailable('Current network authority unavailable') from exc


@router.post('/network-session')
async def network_session(body: NetworkRequest,request: Request,user: CurrentAuthUser,claims: dict=Depends(get_access_token_claims)):
    headers={'Cache-Control':'no-store','Pragma':'no-cache'}
    client=claims.get('azp') or claims.get('client_id')
    if (is_smoke_session(claims) or claims.get('spanopticon_auth')
            or not isinstance(client,str) or not client.strip()
            or (claims.get('azp') and claims.get('client_id') and claims['azp']!=claims['client_id'])):
        raise HTTPException(403,'Unambiguous fresh issuer identity required',headers=headers)
    selected=request.headers.get('X-Tenant-ID')
    if selected and selected!=str(body.tenant_id):
        raise HTTPException(403,'Tenant selection differs',headers=headers)
    try:grant=await current_network(user.sub,body.tenant_id)
    except ScopeUnavailable as exc:raise HTTPException(503,'Network authority unavailable',headers=headers) from exc
    if grant is None:raise HTTPException(403,'Current network administration required',headers=headers)
    base=mint_tenant_session_jwt(claims={**claims,'azp':client,'permissions':grant.permissions,'realm_access':{'roles':[]},'groups':[]},tenant_id=body.tenant_id,extra_roles=['network:admin'])
    payload=jwt.decode(base,settings.usable_api_key_exchange_secret(),algorithms=['HS256'],issuer='https://spanopticon.internal/tenant-session')
    payload.update(scope_version=1,scope_kind='network',organization_id=None,network_id=grant.network_id,
                   scope_generation=grant.generation,scope_manifest_sha256=grant.manifest_sha256)
    token=jwt.encode(payload,settings.usable_api_key_exchange_secret(),algorithm='HS256')
    from auth_service import outbox
    from controlplane_api.event_types import AUTH_TOKEN_ISSUED_V1
    await outbox.publish_auth_event(token=token,tenant_id=body.tenant_id,event_type=AUTH_TOKEN_ISSUED_V1,payload={
        'subject':user.sub,'grant_type':'network_scope','client_id':client,'network_id':grant.network_id,
        'scope_generation':grant.generation,'scope_manifest_sha256':grant.manifest_sha256})
    return JSONResponse({'access_token':token,'expires_in':payload['exp']-payload['iat'],'token_type':'Bearer'},headers=headers)
