"""Synthetic provider signature and code exchange contracts, CI only."""
import json
import time
import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec
from auth_service import linked_oidc_runtime as runtime
from auth_service import linked_oidc_state as state

@pytest.mark.asyncio
async def test_fixed_provider_signature_and_pkce_exchange():
    key=ec.generate_private_key(ec.SECP256R1())
    public=json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))|{'kid':'synthetic','alg':'ES256','use':'sig'}
    now=int(time.time())
    provider=dict(issuer='https://issuer.example',clientId='s3rch',tenant='tenant',tenantClaim='tid',clientSecret='secret',
        tokenEndpoint='https://issuer.example/token',redirectUri='https://test.s3r.ch/callback',jwks={'keys':[public]})
    claims=dict(iss=provider['issuer'],sub='person',tid='tenant',aud='s3rch',nonce='i'*64,iat=now,auth_time=now,exp=now+60)
    token=jwt.encode(claims,key,algorithm='ES256',headers={'kid':'synthetic'})
    with respx.mock(assert_all_called=True) as mock:
        route=mock.post(provider['tokenEndpoint']).mock(return_value=httpx.Response(200,json={'id_token':token}))
        actual,verified=await runtime.exchange(provider,{},'one-time-code','v'*43)
        assert actual==token and verified['sub']=='person'
        body=route.calls[0].request.content.decode()
        assert 'code_verifier='+'v'*43 in body and 'client_secret=secret' in body
        route.mock(return_value=httpx.Response(200,json={'id_token':token[:-8]+'tampered'}))
        with pytest.raises(jwt.InvalidTokenError):await runtime.exchange(provider,{},'code','v'*43)
        route.mock(return_value=httpx.Response(302,headers={'location':'https://foreign.example/token'}))
        with pytest.raises(httpx.HTTPStatusError):await runtime.exchange(provider,{},'code','v'*43)
