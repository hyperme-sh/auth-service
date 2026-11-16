"""Distinct native genesis producer; protected caller owns durable issuance."""
import copy
import hashlib
import json
import struct
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec,utils
from auth_service import first_oidc_link as common

FirstLinkRefused=common.FirstLinkRefused
require=common.require
exact=common.exact
fingerprint=common.fingerprint
replay=common.replay


def lp(values):
    return b''.join(struct.pack('<I',len(part))+part for part in (v.encode('utf-8') for v in values))


def signing_bytes(record):
    return lp(['sociacl-genesis-epub-v1',record['principal'],record['epub'],str(record['issuedAt'])])


def request_nonce(record,binding):
    """Original public signed request and protected identity/deadline, never JSON."""
    exact(record,'v kind principal epub issuedAt keySig attest')
    require(type(record['v']) is int and record['v']==1 and record['kind']=='genesis-epub' and record['attest']=='')
    require(type(record['issuedAt']) is int and 0<=record['issuedAt']<=9007199254740991)
    require(type(binding['expiresAt']) is int and 0<=binding['expiresAt']<=9007199254740991)
    return hashlib.sha256(lp(['auth-first-genesis-provider-v1','1','genesis-epub',record['principal'],record['epub'],
        str(record['issuedAt']),record['keySig'],'',binding['issuer'],binding['tenant'],binding['subject'],
        binding['clientId'],str(binding['expiresAt'])])).hexdigest()


def prepare(record,binding,now):
    exact(binding,'principal epub issuer tenant subject clientId tenantClaim sequence expiresAt')
    nonce=request_nonce(record,binding)
    require(type(now) is int and 0<=record['issuedAt']<=now<record['issuedAt']+120<=9007199254740991)
    require(now<binding['expiresAt'] and type(binding['sequence']) is int and binding['sequence']==0)
    require(record['principal']==binding['principal'] and record['epub']==binding['epub'])
    common.principal_key(record['epub'])
    key=common.principal_key(record['principal']);sig=common.b64(record['keySig'],64)
    key.verify(utils.encode_dss_signature(int.from_bytes(sig[:32]),int.from_bytes(sig[32:])),signing_bytes(record),ec.ECDSA(hashes.SHA256()))
    # Validate protected provider-domain shape independently of browser input.
    require(type(binding['issuer']) is str and common.re.fullmatch(r'https://[!-~]{1,2040}',binding['issuer']))
    require(type(binding['tenant']) is str and common.re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',binding['tenant']))
    require(type(binding['subject']) is str and common.re.fullmatch(r'[!-~]{1,255}',binding['subject']))
    require(type(binding['clientId']) is str and 1<=len(binding['clientId'])<=255)
    require(binding['tenantClaim'] is None or type(binding['tenantClaim']) is str and 1<=len(binding['tenantClaim'])<=255)
    require(len(nonce)==64)
    return copy.deepcopy(record)


def provider_claims(token,record,binding,jwks,now):
    return common.provider_claims(token,{'nonce':request_nonce(record,binding),'issuedAt':record['issuedAt']},binding,jwks,now)


def validate(record,token,binding,provider_jwks,signer,signer_key,now):
    try:
        record=prepare(record,binding,now)
        claims,provider_until=provider_claims(token,record,binding,provider_jwks,now)
        exact(signer,'kid notBefore notAfter')
        require(type(signer['kid']) is str and 1<=len(signer['kid'])<=128)
        require(type(signer['notBefore']) is int and type(signer['notAfter']) is int
                and signer['notBefore']<=record['issuedAt']<=now<signer['notAfter'])
        require(isinstance(signer_key,ec.EllipticCurvePrivateKey) and isinstance(signer_key.curve,ec.SECP256R1))
        deadline=min(record['issuedAt']+120,claims['exp'],binding['expiresAt'],signer['notAfter'],provider_until)
        require(now<deadline)
        digest=fingerprint(dict(record=record,proof=hashlib.sha256(token.encode()).hexdigest(),binding=binding,
            provider=provider_jwks,signer=signer,signerPublic=json.loads(jwt.algorithms.ECAlgorithm.to_jwk(signer_key.public_key()))))
        return record,deadline,digest
    except Exception:raise FirstLinkRefused() from None


def issue(record,token,binding,provider_jwks,signer,signer_key,now):
    record,deadline,digest=validate(record,token,binding,provider_jwks,signer,signer_key,now)
    payload=dict(typ='sociacl-genesis-epub-attest-v1',principal=record['principal'],epub=record['epub'],iat=record['issuedAt'],exp=deadline)
    attestation=jwt.encode(payload,signer_key,algorithm='ES256',headers={'kid':signer['kid']})
    return dict(fingerprint=digest,principal=record['principal'],expiresAt=deadline,attestation=attestation)
