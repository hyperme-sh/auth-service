"""Service-only proof delivery. The existing s3r.ch issuer remains the sole issuer."""
import asyncio
import copy
import secrets
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from auth_service import linked_oidc_runtime as runtime
from auth_service import linked_oidc_state as state
from auth_service.linked_oidc_store import LinkedOidcStore
from auth_service.pairing_routes import PRIVATE, bad_constant
from auth_service.nightly_runtime import admission
import json

router=APIRouter(prefix='/auth/linked-oidc/v1',tags=['Linked OIDC proof'])


@router.post('/{action}')
async def linked_oidc(action: str, request: Request):
    if action not in ('start','exchange','result','cancel'):
        return JSONResponse({'error':'unknown-operation'},status_code=404,headers=PRIVATE)
    try:
        config=runtime.configuration()
        if config is None:
            return JSONResponse({'error':'linked-proof-unavailable'},status_code=503,headers=PRIVATE)
        runtime.authenticate(config,request.headers.get('authorization'))
        if request.headers.get('content-type','').split(';')[0].strip().lower()!='application/json' or request.headers.get('content-encoding','identity')!='identity':
            raise state.LinkedProofRefused()
        slots=request.app.state.linked_oidc_slots
        state.require(not slots.locked())
        async with slots, asyncio.timeout(20):
            raw=bytearray()
            async for part in request.stream():
                state.require(len(raw)+len(part)<=24576);raw.extend(part)
            body=json.loads(raw,object_pairs_hook=runtime.unique,parse_constant=bad_constant)
            state.fields(body,'challenge state code' if action=='exchange' else 'challenge')
            original=body['challenge'];provider=config['provider']
            bound=admission.get()
            run=None if bound is None else {k:bound[k] for k in ('run','generation')}
            store=LinkedOidcStore(request.app.state.async_engine)
            def current():
                state.require(runtime.configuration()==config)
                state.require(bound is None or not bound.get('_closed',False))
            def transition(rows,key,now):
                current()
                state.challenge(original,provider,now)
                row=rows.get(key)
                if action=='start':
                    if row is None:
                        row=state.begin(original,provider,now=now,state=secrets.token_urlsafe(32),verifier=secrets.token_urlsafe(48),run=run)
                        rows[key]=row
                    state.bound(row,provider,original,now,run)
                    state.require(row['phase']=='pending')
                    return {'authorizationUrl':state.authorization_url(row,provider)}
                state.require(row is not None)
                if action=='cancel' and row.get('phase')=='cancelled':
                    state.require(row['challenge']==original and row['run']==run)
                    return {'status':'cancelled'}
                state.bound(row,provider,original,now,run)
                if action=='cancel':
                    state.cancel(row)
                    return {'status':'cancelled'}
                if action=='result':
                    sealed=state.result(row,provider,original,now=now,run=run)
                    return {'idToken':runtime.unseal(config,original,sealed)}
                verifier=state.claim_exchange(row,provider,original,state=body['state'],now=now,run=run)
                return copy.deepcopy(row),verifier
            result=await store.execute(provider,original,run,transition)
            if action=='exchange':
                row,verifier=result
                # A crash or failed provider call leaves exchanging terminal for
                # this challenge. Never retry the one-time provider code.
                token,claims=await runtime.exchange(provider,row,body['code'],verifier)
                def finish(rows,key,now):
                    current()
                    live=rows.get(key);state.require(live is not None)
                    state.verify_claims(claims,live,provider,now)
                    state.complete(live,provider,original,sealed_proof=runtime.seal(config,original,token),now=now,run=run)
                    return {'idToken':token}
                result=await store.execute(provider,original,run,finish)
            current()
            return JSONResponse({'version':1,**result},headers=PRIVATE)
    except state.LinkedProofRefused:
        return JSONResponse({'error':'linked-proof-refused'},status_code=409,headers=PRIVATE)
    except Exception:
        # Never reflect provider tokens, code, private configuration or SQL.
        return JSONResponse({'error':'linked-proof-unavailable'},status_code=503,headers=PRIVATE)
