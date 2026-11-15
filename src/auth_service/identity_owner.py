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


async def supports_wallet_commands():
    """Older User owners keep the existing bind contract during rolling updates."""
    from auth_service.siwe_nonces import SiweStoreUnavailable
    url = os.environ.get('AUTH_IDENTITY_OWNER_URL', '').rstrip('/')
    token = os.environ.get('AUTH_IDENTITY_OWNER_TOKEN', '')
    if not url or not token:
        raise SiweStoreUnavailable('Identity owner HTTP configuration is required')
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(url+'/api/v1/internal/identity/wallet-command-contract',
                                        headers={'Authorization':'Bearer '+token})
        if response.status_code in (404, 405):
            return False
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or body.get('wallet_command_version') not in (0, 1):
            raise ValueError('Unsupported wallet command contract')
        return body['wallet_command_version'] == 1
    except (httpx.HTTPError, ValueError) as exc:
        raise SiweStoreUnavailable('Wallet owner contract unavailable') from exc
