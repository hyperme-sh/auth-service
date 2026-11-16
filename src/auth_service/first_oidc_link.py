"""First-link attestation primitives. No route, storage or live configuration.

The caller must atomically bind the declared credential to one enrolled principal
and persist exact output before returning it. ACL remains the final admission gate.
"""
import base64
import copy
import hashlib
import json
import re
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
import jwt


class FirstLinkRefused(ValueError):
    def __init__(self):
        super().__init__('First OIDC link refused')


def require(value):
    if not value:
        raise FirstLinkRefused()


def exact(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def b64(value, size):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]+', value))
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    require(len(raw) == size and base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == value)
    return raw


def principal_key(value):
    require(type(value) is str and len(value) == 87 and value[43] == '.')
    return ec.EllipticCurvePublicNumbers(int.from_bytes(b64(value[:43], 32)),
        int.from_bytes(b64(value[44:], 32)), ec.SECP256R1()).public_key()


def signing_bytes(record):
    values = ['sociacl-link-oidc-v1', record['principal'], record['cred']['iss'],
              record['cred']['tenant'], record['cred']['sub'], str(record['issuedAt']), record['nonce']]
    return b''.join(struct.pack('<I', len(part)) + part for part in (v.encode() for v in values))


def prepare(record, binding, now):
    """Binding is protected owner input, never supplied by the browser body.

    Sequence zero is a binding constraint, not an extra native record field.
    Tenant is selected by the declared issuer/client/subject mapping; a provider
    tenant claim is checked only when that explicit mapper is configured.
    """
    exact(binding, 'principal issuer tenant subject clientId tenantClaim sequence expiresAt')
    require(type(now) is int and now >= 0 and type(binding['expiresAt']) is int and now < binding['expiresAt'])
    require(type(binding['sequence']) is int and binding['sequence'] == 0)
    require(binding['tenantClaim'] is None or type(binding['tenantClaim']) is str and 1 <= len(binding['tenantClaim']) <= 255)
    exact(record, 'v kind principal issuedAt cred nonce keySig attest')
    exact(record['cred'], 'iss tenant sub')
    require(type(record['v']) is int and record['v'] == 1 and record['kind'] == 'oidc' and record['attest'] == '')
    require(record['principal'] == binding['principal'])
    require(record['cred'] == dict(iss=binding['issuer'], tenant=binding['tenant'], sub=binding['subject']))
    require(type(record['issuedAt']) is int and 0 <= record['issuedAt'] <= now < record['issuedAt'] + 120 <= 9007199254740991)
    require(type(record['nonce']) is str and re.fullmatch(r'[A-Za-z0-9]{8,128}', record['nonce']))
    require(type(binding['issuer']) is str and re.fullmatch(r'https://[!-~]{1,2040}', binding['issuer']))
    require(type(binding['tenant']) is str and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', binding['tenant']))
    require(type(binding['subject']) is str and re.fullmatch(r'[!-~]{1,255}', binding['subject']))
    require(type(binding['clientId']) is str and 1 <= len(binding['clientId']) <= 255)
    key = principal_key(record['principal'])
    sig = b64(record['keySig'], 64)
    key.verify(utils.encode_dss_signature(int.from_bytes(sig[:32]), int.from_bytes(sig[32:])),
               signing_bytes(record), ec.ECDSA(hashes.SHA256()))
    return copy.deepcopy(record)


def provider_claims(token, record, binding, jwks, now):
    require(type(token) is str and 1 <= len(token) <= 16384)
    header = jwt.get_unverified_header(token)
    require(header.get('alg') in ('RS256', 'PS256', 'ES256') and type(header.get('kid')) is str)
    require(type(jwks) is dict and type(jwks.get('keys')) is list and 1 <= len(jwks['keys']) <= 16)
    keys = [k for k in jwks['keys'] if k.get('kid') == header['kid']]
    require(len(keys) == 1)
    key = keys[0]
    require(key.get('alg', header['alg']) == header['alg'] and key.get('use', 'sig') == 'sig'
            and key.get('key_ops', ['verify']) == ['verify'])
    require(type(key.get('notBefore')) is int and type(key.get('notAfter')) is int
            and key['notBefore'] <= now < key['notAfter'])
    claims = jwt.decode(token, jwt.PyJWK.from_dict(key).key, algorithms=[header['alg']],
        issuer=binding['issuer'], audience=binding['clientId'],
        options={'require':['iss','sub','aud','iat','exp','nonce','auth_time'],
                 'verify_iat':False,'verify_exp':False,'verify_nbf':False})
    require(claims['sub'] == binding['subject'] and claims['nonce'] == record['nonce'])
    require(claims['aud'] in (binding['clientId'], [binding['clientId']]) and claims.get('azp', binding['clientId']) == binding['clientId'])
    for name in ('iat', 'auth_time'):
        require(type(claims[name]) is int and record['issuedAt'] <= claims[name] <= now)
    require(type(claims['exp']) is int and now < claims['exp'])
    require('nbf' not in claims or type(claims['nbf']) is int and claims['nbf'] <= now)
    if binding['tenantClaim'] is not None:
        require(claims.get(binding['tenantClaim']) == binding['tenant'])
    return claims


def validate(record, token, binding, provider_jwks, signer, signer_key, now):
    """Verify a request and derive its immutable transaction identity without signing."""
    try:
        record = prepare(record, binding, now)
        claims = provider_claims(token, record, binding, provider_jwks, now)
        exact(signer, 'kid notBefore notAfter')
        require(type(signer['kid']) is str and 1 <= len(signer['kid']) <= 128)
        require(type(signer['notBefore']) is int and type(signer['notAfter']) is int
                and signer['notBefore'] <= record['issuedAt'] <= now < signer['notAfter'])
        require(isinstance(signer_key, ec.EllipticCurvePrivateKey) and isinstance(signer_key.curve, ec.SECP256R1))
        deadline = min(record['issuedAt'] + 120, claims['exp'], binding['expiresAt'], signer['notAfter'])
        require(now < deadline)
        digest = fingerprint(dict(record=record, proof=hashlib.sha256(token.encode()).hexdigest(),
                    binding=binding, provider=provider_jwks, signer=signer,
                    signerPublic=json.loads(jwt.algorithms.ECAlgorithm.to_jwk(signer_key.public_key()))))
        return record, deadline, digest
    except Exception:
        raise FirstLinkRefused() from None


def issue(record, token, binding, provider_jwks, signer, signer_key, now):
    """Candidate output for an atomic first-link commit, never an HTTP response."""
    record, deadline, digest = validate(record, token, binding, provider_jwks, signer, signer_key, now)
    payload = dict(typ='sociacl-oidc-attest-v1', **record['cred'], principal=record['principal'],
                   iat=record['issuedAt'], exp=deadline, nonce=record['nonce'])
    attestation = jwt.encode(payload, signer_key, algorithm='ES256', headers={'kid':signer['kid']})
    return dict(fingerprint=digest, principal=record['principal'], expiresAt=deadline, attestation=attestation)


def replay(saved, expected_fingerprint, principal, now):
    """Pure exact retry decision, used inside the owner transaction."""
    exact(saved, 'fingerprint principal expiresAt attestation')
    require(saved['fingerprint'] == expected_fingerprint and saved['principal'] == principal)
    require(type(now) is int and type(saved['expiresAt']) is int and now < saved['expiresAt'])
    require(type(saved['attestation']) is str and 1 <= len(saved['attestation']) <= 16384)
    return saved['attestation']
