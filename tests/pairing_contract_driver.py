"""Line-oriented ASGI unit adapter for the packed SDK contract; no network."""
import asyncio
import json
import sys
from fastapi import FastAPI
import httpx
import auth_service.pairing_routes as routes
from auth_service.pairing_state import empty, apply


async def main():
    state=empty()
    class Store:
        async def execute(self,scope,**operation):return apply(state,scope=scope,now=1700000000000,**operation)
    async def claims(token):
        if token!='synthetic':raise ValueError()
        return {'sub':'source-person','iss':'https://issuer.example','tenant_id':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','scope':'auth:device:transfer'}
    routes.get_access_token_claims=claims
    app=FastAPI();app.include_router(routes.router)
    scope={'sourceOrigin':'https://source.example','destinationOrigin':'https://destination.example','application':'unit','tenant':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','audience':'test'}
    app.state.pairing_store=Store();app.state.pairing_scopes=[scope];app.state.pairing_slots=asyncio.Semaphore(8)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://unit') as client:
        for line in sys.stdin:
            value=json.loads(line);headers=value['headers'];role=headers['X-Pairing-Role']
            headers['Origin']=scope['sourceOrigin' if role=='sender' else 'destinationOrigin']
            if role=='sender':headers['Authorization']='Bearer synthetic'
            response=await client.post('/auth/sea-device-link/v1/sessions/'+value['session']+'/'+value['action'],
                json={'scope':value['scope'],'payload':value['payload']},headers=headers)
            print(json.dumps({'status':response.status_code,'body':response.json()}),flush=True)


if __name__=='__main__':asyncio.run(main())
