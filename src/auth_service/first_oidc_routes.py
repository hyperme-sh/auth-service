"""Protected first-link issuance. No identity/session creation or reader registration."""
import asyncio
import json
import time
from fastapi import APIRouter,Request
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from auth_service import first_oidc_link as core, first_oidc_runtime as runtime
from auth_service.first_oidc_store import FirstOidcStore
from auth_service import nightly_runtime as nightly
from auth_service.pairing_routes import PRIVATE,bad_constant

router=APIRouter(prefix='/auth/first-oidc-link/v1',tags=['First OIDC link'])

@router.post('/{action}')
async def first_oidc(action:str,request:Request):
    if action not in ('issue','cancel'):
        return JSONResponse({'error':'unknown-operation'},status_code=404,headers=PRIVATE)
    try:
        config=runtime.configuration()
        if config is None:return JSONResponse({'error':'first-link-unavailable'},status_code=503,headers=PRIVATE)
        runtime.authenticate(config,request.headers.get('authorization'))
        core.require(request.headers.get('content-type','').split(';')[0].strip().lower()=='application/json'
                     and request.headers.get('content-encoding','identity')=='identity')
        slots=request.app.state.first_oidc_slots;core.require(not slots.locked())
        async with slots,asyncio.timeout(20):
            raw=bytearray()
            async for chunk in request.stream():
                core.require(len(raw)+len(chunk)<=24576);raw.extend(chunk)
            body=json.loads(raw,object_pairs_hook=runtime.unique,parse_constant=bad_constant)
            core.exact(body,'record idToken' if action=='issue' else 'record')
            binding=runtime.select(config,body['record'])
            nightly_config=nightly.configuration()
            bound=nightly.admission.get()
            managed=nightly_config is not None and any(s['subject']==binding['subject'] for s in nightly_config['scopes'].values())
            core.require(not request.headers.get('x-nightly-run-grant') or bound is not None)
            if managed or bound is not None:
                core.require(bound is not None and not bound.get('_closed',False) and nightly_config is not None)
                scope=bound['scope']
                core.require(nightly_config['scopes'].get(scope['suite'])==scope
                             and scope['subject']==binding['subject'] and scope['tenant']==binding['tenant']
                             and scope['issuer']==binding['issuer'] and binding['clientId'] in scope['clients'])
            if action=='issue':
                claims,_=core.provider_claims(body['idToken'],body['record'],binding,config['providerJwks'],int(time.time()))
                await nightly.verify_claims(claims)
            def current():
                core.require(runtime.configuration()==config and nightly.configuration()==nightly_config
                             and nightly.admission.get() is bound
                             and (bound is None or not bound.get('_closed',False)))
            store=FirstOidcStore(request.app.state.async_engine)
            if action=='cancel':
                status=await store.cancel(body['record'],binding,current)
                result={'status':status}
            else:
                signing_key=load_pem_private_key(config['signingKeyPem'].encode(),password=None)
                attestation=await store.issue(body['record'],body['idToken'],binding,config['providerJwks'],config['signer'],signing_key,current)
                result={'attestation':attestation}
            current()
            return JSONResponse({'version':1,**result},headers=PRIVATE)
    except core.FirstLinkRefused:
        return JSONResponse({'error':'first-link-refused'},status_code=409,headers=PRIVATE)
    except Exception:
        return JSONResponse({'error':'first-link-unavailable'},status_code=503,headers=PRIVATE)
