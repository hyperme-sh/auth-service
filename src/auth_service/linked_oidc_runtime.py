"""Private proof-broker configuration and provider verification, disabled absent a file."""
import asyncio
import hmac
import json
import os
import stat
from pathlib import Path
from urllib.parse import urlsplit
import httpx
import jwt
from cryptography.fernet import Fernet
from auth_service import linked_oidc_state as state


def unique(pairs):
    result=dict(pairs)
    state.require(len(result)==len(pairs))
    return result


def configuration():
    name=os.environ.get('AUTH_LINKED_OIDC_CONFIG_FILE')
    if name is None:return None
    path=Path(name)
    state.require(path.is_absolute() and path.resolve()==path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        state.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_mode & 0o077==0)
        raw=stream.read(65537)
    state.require(len(raw)<=65536)
    value=json.loads(raw,object_pairs_hook=unique)
    state.fields(value,'version serviceToken sealingKey provider')
    state.require(type(value['version']) is int and value['version']==1)
    state.require(type(value['serviceToken']) is str and state.TOKEN.fullmatch(value['serviceToken']))
    Fernet(value['sealingKey'].encode())
    provider=value['provider']
    state.fields(provider,'origin issuer tenant tenantClaim clientId clientSecret authorizationEndpoint tokenEndpoint redirectUri jwks')
    state.canonical_origin(provider['origin'])
    for name in ('issuer','authorizationEndpoint','tokenEndpoint','redirectUri'):
        url=provider[name];p=urlsplit(url)
        state.require(type(url) is str and p.scheme=='https' and p.hostname and p.username is None and p.password is None and not p.query and not p.fragment)
    for name in ('tenant','tenantClaim','clientId','clientSecret'):
        state.require(type(provider[name]) is str and 1<=len(provider[name])<=4096)
    state.require(provider['redirectUri'].startswith(provider['origin']+'/'))
    state.require(type(provider['jwks']) is dict and type(provider['jwks'].get('keys')) is list and 1<=len(provider['jwks']['keys'])<=16)
    return value


def authenticate(config, authorization):
    state.require(config is not None and type(authorization) is str)
    state.require(hmac.compare_digest(authorization.encode(),('Bearer '+config['serviceToken']).encode()))


def seal(config, challenge, id_token):
    return Fernet(config['sealingKey'].encode()).encrypt(json.dumps(
        {'challenge':state.fingerprint(challenge),'idToken':id_token},separators=(',',':')).encode()).decode()


def unseal(config, challenge, sealed):
    value=json.loads(Fernet(config['sealingKey'].encode()).decrypt(sealed.encode()))
    state.fields(value,'challenge idToken')
    state.require(value['challenge']==state.fingerprint(challenge))
    return value['idToken']


async def exchange(provider, row, code, verifier):
    state.require(type(code) is str and 1<=len(code)<=4096)
    async with httpx.AsyncClient(timeout=10,follow_redirects=False) as client:
        async with client.stream('POST',provider['tokenEndpoint'],data={
            'grant_type':'authorization_code','code':code,'redirect_uri':provider['redirectUri'],
            'client_id':provider['clientId'],'client_secret':provider['clientSecret'],'code_verifier':verifier}) as response:
            response.raise_for_status()
            raw=bytearray()
            async for part in response.aiter_bytes():
                state.require(len(raw)+len(part)<=65536);raw.extend(part)
    value=json.loads(raw,object_pairs_hook=unique)
    token=value.get('id_token')
    state.require(type(token) is str and 1<=len(token)<=16384)
    header=jwt.get_unverified_header(token)
    state.require(header.get('alg') in ('RS256','PS256','ES256') and type(header.get('kid')) is str)
    keys=[k for k in provider['jwks']['keys'] if k.get('kid')==header['kid'] and k.get('use','sig')=='sig'
          and k.get('alg',header['alg'])==header['alg'] and 'verify' in k.get('key_ops',['verify'])]
    state.require(len(keys)==1)
    claims=jwt.decode(token,jwt.PyJWK.from_dict(keys[0]).key,algorithms=[header['alg']],
        issuer=provider['issuer'],audience=provider['clientId'],
        options={'require':['iss','sub','aud','iat','exp','nonce','auth_time']})
    from auth_service.nightly_runtime import verify_claims
    await verify_claims(claims)
    return token,claims
