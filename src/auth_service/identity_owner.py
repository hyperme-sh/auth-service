"""Typed identity commands cross HTTP; auth never opens the user database."""
import os
import httpx

async def call(operation, **payload):
    url = os.environ.get('AUTH_IDENTITY_OWNER_URL', '').rstrip('/')
    token = os.environ.get('AUTH_IDENTITY_OWNER_TOKEN', '')
    if not url or not token:
        raise RuntimeError('Identity owner HTTP configuration is required')
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        response = await client.post(url+'/api/v1/internal/identity/'+operation,
                                    json=payload, headers={'Authorization':'Bearer '+token})
        if response.status_code == 409:
            detail=response.json().get('detail','Identity owner rejected the command')
            if operation=='enroll':
                from auth_service.enrollment import EnrollmentError
                raise EnrollmentError(detail)
            if operation in ('bind-wallet','get-wallet'):
                from auth_service.siwe import SiweError
                raise SiweError(detail)
        response.raise_for_status()
        return response.json()
