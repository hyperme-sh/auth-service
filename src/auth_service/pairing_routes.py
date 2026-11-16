"""Versioned public receiver bootstrap and authenticated sender relay routes."""
import asyncio
import hashlib
import json
from time import monotonic
from typing import Literal
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from auth_service.claims import tenant_uuid_from_claims, scopes_from_claims
from auth_service.deps import get_access_token_claims
from auth_service.pairing_wire import binary, capability, b64, fields, scope, MAX_BODY
from auth_service.pairing_store import PairingUnavailable

PRIVATE = {'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}
router = APIRouter(prefix='/auth/sea-device-link/v1', tags=['SEA pairing v1'])


class AnonymousLimiter:
    """Bound untrusted request work separately from durable session quotas."""
    def __init__(self): self.window = None; self.clients = {}

    def allow(self, client):
        window = int(monotonic()) // 60
        if window != self.window: self.window = window; self.clients.clear()
        if client not in self.clients and len(self.clients) >= 1024: return False
        count = self.clients.get(client, 0)
        if count >= 120: return False
        self.clients[client] = count + 1
        return True


def unique(pairs):
    value = dict(pairs)
    if len(value) != len(pairs): raise ValueError()
    return value


def bad_constant(_): raise ValueError()


def response(status, result): return JSONResponse({'v':1,'result':result}, status_code=status, headers=PRIVATE)


@router.post('/sessions/{session}/{action}', openapi_extra={
    'requestBody': {'required':True,'content':{'application/json':{'schema':{
        'type':'object','additionalProperties':False,'required':['scope','payload'],
        'properties':{'scope':{'type':'object','description':'Exact configured SDK Scope'},
            'payload':{'type':'object','description':'create: {request,joinHash}; join: SDK Offer; send: SDK Envelope; complete: SDK Completion; reads/cancel: {}'}}}}}},
    'description':'Receiver bootstrap uses X-Pairing-Capability only. Sender operations also require an authorized tenant bearer. Join additionally requires X-Pairing-Join. All calls require exact Origin and X-Pairing-Role. No key bytes, tokens or capabilities in URLs.'})
async def pairing(session: str, action: Literal['create','join','offer','send','receive','complete','completed','cancel'], request: Request):
    slots = request.app.state.pairing_slots
    if slots.locked(): return response(429, {'error':'pairing-busy'})
    async with slots:
        try:
            async with asyncio.timeout(12): return await execute_pairing(session, action, request)
        except TimeoutError: return response(503, {'error':'pairing-unavailable'})


async def execute_pairing(session, action, request):
    store = request.app.state.pairing_store
    if store is None: return response(503, {'error':'pairing-unavailable'})
    # Every caller is untrusted here, including claimed senders with a bearer.
    # Charge before reading bodies or invoking token validation.
    limiter = getattr(request.app.state, 'pairing_anonymous_limiter', None)
    if limiter is None:
        limiter = request.app.state.pairing_anonymous_limiter = AnonymousLimiter()
    # ASGI client identity only: never read untrusted forwarding headers.
    client = request.client.host if request.client else 'unknown'
    if not limiter.allow(client): return response(429, {'error':'pairing-busy'})
    try:
        binary(session, 32)
        role = request.headers.get('x-pairing-role')
        if role not in ('receiver','sender'): raise ValueError()
        cap_hash = capability(request.headers.get('x-pairing-capability'))
        if request.headers.get('content-type','').split(';')[0].strip().lower() != 'application/json' or request.headers.get('content-encoding','identity') != 'identity':
            return response(415, {'error':'pairing-refused'})
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > MAX_BODY: return response(413, {'error':'pairing-refused'})
            data.extend(chunk)
        body = json.loads(data.decode('utf8'), object_pairs_hook=unique, parse_constant=bad_constant)
        fields(body, 'scope payload'); current_scope = scope(body['scope'])
        if current_scope not in request.app.state.pairing_scopes: return response(403, {'error':'pairing-refused'})
        expected_origin = current_scope['sourceOrigin' if role == 'sender' else 'destinationOrigin']
        if request.headers.get('origin') != expected_origin: return response(403, {'error':'pairing-refused'})
        subject = None
        if role == 'sender':
            try:
                auth = request.headers.get('authorization','')
                if not auth.startswith('Bearer '): raise ValueError()
                claims = await get_access_token_claims(auth[7:])
                if (str(tenant_uuid_from_claims(claims)) != current_scope['tenant']
                        or 'auth:device:transfer' not in scopes_from_claims(claims)
                        or claims.get('spanopticon_auth') == 'api_key' or claims.get('account_type') == 'service'
                        or not isinstance(claims.get('sub'),str) or not claims['sub']): raise ValueError()
                subject = hashlib.sha256(json.dumps([claims.get('iss'),claims['sub'],current_scope['tenant']]).encode()).hexdigest()
            except Exception: return response(401, {'error':'pairing-refused'})
        join_hash = b64(hashlib.sha256(binary(request.headers.get('x-pairing-join'),32)).digest()) if action == 'join' else None
    except (ValueError, TypeError, RecursionError): return response(400, {'error':'pairing-refused'})
    try:
        status, result = await store.execute(current_scope, action=action, session=session, role=role,
            cap_hash=cap_hash, subject=subject, payload=body['payload'], join_hash=join_hash)
        return response(status, result)
    except PairingUnavailable: return response(503, {'error':'pairing-unavailable'})
