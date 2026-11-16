"""Pure transitions for proof delivery bound to one existing linked challenge."""
import copy
import hashlib
import hmac
import json
import re
from urllib.parse import urlsplit, urlencode

TOKEN = re.compile(r'^[A-Za-z0-9_-]{43,128}$')

class LinkedProofRefused(ValueError):
    pass


def require(condition):
    if not condition:
        raise LinkedProofRefused('Linked proof refused')


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def canonical_origin(value):
    require(type(value) is str)
    p = urlsplit(value)
    require(p.scheme == 'https' and p.hostname and p.username is None and p.password is None
            and not p.query and not p.fragment and not p.path and value == 'https://' + p.netloc)
    return value


def challenge(value, provider, now):
    fields(value, 'token id issuedAt expiresAt origin credential')
    require(type(value['token']) is str and 1 <= len(value['token']) <= 16384)
    require(type(value['id']) is str and TOKEN.fullmatch(value['id']))
    require(type(value['issuedAt']) is int and type(value['expiresAt']) is int
            and 0 <= value['issuedAt'] <= now < value['expiresAt'] <= value['issuedAt'] + 300)
    require(canonical_origin(value['origin']) == provider['origin'])
    credential = value['credential']
    fields(credential, 'kind iss tenant sub')
    require(credential['kind'] == 'oidc' and credential['iss'] == provider['issuer']
            and credential['tenant'] == provider['tenant'] and type(credential['sub']) is str
            and 1 <= len(credential['sub']) <= 255 and not any(ord(c) < 32 for c in credential['sub']))
    return copy.deepcopy(value)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def begin(value, provider, *, now, state, verifier, run):
    original = challenge(value, provider, now)
    require(TOKEN.fullmatch(state) and TOKEN.fullmatch(verifier))
    # The private service client vouches for the issuer-created challenge; Auth
    # never interprets the challenge token as authority to select a SEA key.
    return dict(version=1, challenge=original, provider=fingerprint(provider),
                state=state, verifier=verifier, run=copy.deepcopy(run), phase='pending', sealedProof=None)


def bound(row, provider, expected, now, run):
    require(type(row) is dict and row.get('version') == 1 and row.get('provider') == fingerprint(provider))
    require(row.get('run') == run)
    require(row['challenge'] == expected)
    challenge(row['challenge'], provider, now)
    require(row['phase'] not in ('cancelled', 'failed'))


def authorization_url(row, provider):
    from base64 import urlsafe_b64encode
    proof = urlsafe_b64encode(hashlib.sha256(row['verifier'].encode()).digest()).rstrip(b'=').decode()
    return provider['authorizationEndpoint'] + '?' + urlencode(dict(
        client_id=provider['clientId'], response_type='code', response_mode='form_post',
        scope='openid', redirect_uri=provider['redirectUri'], state=row['state'],
        nonce=row['challenge']['id'], code_challenge=proof, code_challenge_method='S256',
        prompt='login', max_age='0'))


def claim_exchange(row, provider, expected, *, state, now, run):
    bound(row, provider, expected, now, run)
    require(type(state) is str and hmac.compare_digest(row['state'], state))
    require(row['phase'] == 'pending')
    row['phase'] = 'exchanging'
    return row['verifier']


def verify_claims(claims, row, provider, now):
    """Called only after the provider ID token signature has been verified."""
    credential = row['challenge']['credential']
    require(claims.get('iss') == provider['issuer'] and claims.get('sub') == credential['sub'])
    require(claims.get(provider['tenantClaim']) == credential['tenant'])
    require(claims.get('aud') in (provider['clientId'], [provider['clientId']]))
    require(claims.get('azp', provider['clientId']) == provider['clientId'])
    require(claims.get('nonce') == row['challenge']['id'])
    for key in ('iat', 'auth_time'):
        require(type(claims.get(key)) is int and row['challenge']['issuedAt'] <= claims[key] <= now)
    require(type(claims.get('exp')) is int and now < claims['exp'])


def complete(row, provider, expected, *, sealed_proof, now, run):
    bound(row, provider, expected, now, run)
    require(row['phase'] == 'exchanging' and type(sealed_proof) is str and 1 <= len(sealed_proof) <= 32768)
    row['phase'], row['sealedProof'], row['verifier'] = 'proved', sealed_proof, ''


def cancel(row):
    row['phase'], row['sealedProof'], row['verifier'] = 'cancelled', None, ''


def result(row, provider, expected, *, now, run):
    bound(row, provider, expected, now, run)
    require(row['phase'] == 'proved' and type(row['sealedProof']) is str)
    # Exact readback is not another provider exchange or another SEA challenge.
    return row['sealedProof']
