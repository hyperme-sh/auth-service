"""User-owned identity operations authenticated exclusively as auth-service."""
import hmac
import os
import uuid
from typing import Literal
from dataclasses import asdict
from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel, ConfigDict
from auth_service.schemas import AuthMeResponse

router = APIRouter(prefix='/internal/identity')

class Command(BaseModel):
    model_config = ConfigDict(extra='forbid')
    claims: dict | None = None
    user: AuthMeResponse | None = None
    tenant_id: uuid.UUID | None = None
    requested: list[str] | None = None
    subject: str | None = None
    email: str | None = None
    wallet_address: str | None = None


def authenticate(request: Request):
    expected = os.environ.get('AUTH_IDENTITY_OWNER_TOKEN','')
    if not expected:
        raise HTTPException(503,'Identity command credential is not configured')
    if not hmac.compare_digest(request.headers.get('Authorization','').encode(),('Bearer '+expected).encode()):
        raise HTTPException(401,'Auth-service identity credential required')


@router.post('/{operation}',dependencies=[Depends(authenticate)])
async def execute(operation: Literal['enroll','tenant-switch','tenant-switch-current','host-setup','host-scope','session-member','bind-wallet','get-wallet','seed-operator','seed-host','provision-operator'], command: Command, request: Request):
    from user_service.identity_enrollment import grant_held_roles
    from user_service.identity_tenant_switch import authorize_tenant_switch
    from user_service.identity_wallet_bind import upsert_wallet_binding, get_wallet_binding
    try:
        async with request.app.state.session_maker() as session:
            async with session.begin():
                from user_service.authority_routes import enabled
                if enabled() and operation in ('seed-operator','seed-host','provision-operator'):
                    # New authority comes only from the configured bootstrap.
                    # A login must never recreate legacy roles or memberships.
                    return None
                if operation in ('host-setup', 'host-scope', 'session-member'):
                    if set(command.model_dump(exclude_none=True)) - {'subject', 'tenant_id'}:
                        raise HTTPException(422, 'Membership accepts only subject and tenant')
                    if (command.tenant_id is None or not command.subject
                            or not command.subject.strip() or len(command.subject) > 512):
                        raise HTTPException(422, 'Verified subject and target tenant required')
                    if operation == 'host-scope':
                        from user_service.identity_host_setup import authorize_host_organization as authorize
                    elif operation == 'host-setup':
                        from user_service.identity_host_setup import authorize_host_setup as authorize
                    else:
                        from user_service.identity_session_member import authorize_session_member as authorize
                    result = await authorize(command.subject, command.tenant_id, session)
                    return None if result is None else asdict(result)
                if operation == 'provision-operator':
                    from auth_service.operator_binding import eligible, ROLE
                    from user_service.identity_test_seed import provision_operator
                    if command.claims is None or command.tenant_id is None or not eligible(command.claims, command.tenant_id):
                        raise HTTPException(403, 'Production operator binding required')
                    return await provision_operator(command.claims, command.tenant_id,
                        email=command.claims['email'].strip().lower(), role_name=ROLE,
                        permissions=(), session=session)
                if operation in ('seed-operator','seed-host'):
                    if command.claims is None or command.tenant_id is None:
                        raise HTTPException(422,'Verified claims and tenant required')
                    from user_service.identity_test_seed import provision_test_operator,ensure_seeded_host_role
                    handler=provision_test_operator if operation=='seed-operator' else ensure_seeded_host_role
                    return await handler(command.claims,command.tenant_id,session)
                if operation in ('enroll','tenant-switch','tenant-switch-current'):
                    if command.user is None:
                        raise HTTPException(422,'Verified identity required')
                    if operation == 'enroll':
                        result = await grant_held_roles(session,command.user,tenant_id=command.tenant_id,requested=command.requested)
                    else:
                        if command.tenant_id is None:
                            raise HTTPException(422,'Target tenant required')
                        result = await authorize_tenant_switch(command.user,command.tenant_id,session)
                else:
                    if not command.subject:
                        raise HTTPException(422,'Verified subject required')
                    if operation == 'get-wallet':
                        result = await get_wallet_binding(session,command.subject)
                    else:
                        if not command.wallet_address:
                            raise HTTPException(422,'Verified wallet required')
                        result = await upsert_wallet_binding(session,keycloak_sub=command.subject,email=command.email,wallet_address=command.wallet_address)
                return None if result is None else asdict(result)
    except ValueError as exc:
        raise HTTPException(409,str(exc)) from exc



@router.get('/domain')
async def tenant_domain(request: Request, host: str):
    from sqlalchemy import select,or_
    from controlplane_db.models import Tenant
    from controlplane_api.utils import is_subdomain
    expected=os.environ.get('TENANT_OWNER_TOKEN','')
    if not expected or not hmac.compare_digest(request.headers.get('authorization','').encode(),('Bearer '+expected).encode()):
        raise HTTPException(401,'Tenant owner credential required')
    host=host.lower().strip()
    if not host or len(host)>253 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in host):
        raise HTTPException(400,'Invalid tenant hostname')
    async with request.app.state.session_maker() as session:
        conditions=[Tenant.custom_domain==host]
        if is_subdomain(host):conditions.append(Tenant.subdomain==host.split('.')[0])
        tenant=(await session.execute(select(Tenant.id).where(or_(*conditions),Tenant.is_active.is_(True)))).scalar_one_or_none()
        if tenant is None:raise HTTPException(404,'Tenant hostname unavailable')
        return {'tenant_id':str(tenant)}
