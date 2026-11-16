"""Synthetic native signature contracts, CI only; no installed route."""
import base64
import copy
import json
import pytest
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from auth_service import first_oidc_link as s


def enc(raw):return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()

def fixture(now=100):
    owner=ec.derive_private_key(1,ec.SECP256R1());public=owner.public_key().public_numbers()
    principal=enc(public.x.to_bytes(32))+'.'+enc(public.y.to_bytes(32))
    binding=dict(principal=principal,issuer='https://issuer.example',tenant='00000000-0000-0000-0000-000000000001',
                 subject='declared-person',clientId='s3rch',tenantClaim=None,sequence=0,expiresAt=now+400)
    record=dict(v=1,kind='oidc',principal=principal,issuedAt=now,cred=dict(iss=binding['issuer'],tenant=binding['tenant'],sub=binding['subject']),nonce='a'*64,keySig='',attest='')
    r,t=utils.decode_dss_signature(owner.sign(s.signing_bytes(record),ec.ECDSA(hashes.SHA256())))
    record['keySig']=enc(r.to_bytes(32)+t.to_bytes(32))
    provider=ec.generate_private_key(ec.SECP256R1());signer=ec.generate_private_key(ec.SECP256R1())
    jwks={'keys':[json.loads(jwt.algorithms.ECAlgorithm.to_jwk(provider.public_key()))|dict(kid='provider',alg='ES256',use='sig',key_ops=['verify'],notBefore=now-100,notAfter=now+900)]}
    claims=dict(iss=binding['issuer'],sub=binding['subject'],aud=binding['clientId'],nonce=record['nonce'],iat=now,auth_time=now,exp=now+100)
    token=lambda c=claims:jwt.encode(c,provider,algorithm='ES256',headers={'kid':'provider'})
    return record,binding,jwks,dict(kid='owner-witness',notBefore=now-100,notAfter=now+900),signer,token,claims


def test_native_claims_and_byte_identical_original_deadline_retry():
    r,b,j,k,signer,token,_=fixture();out=s.issue(r,token(),b,j,k,signer,101)
    claims=jwt.decode(out['attestation'],signer.public_key(),algorithms=['ES256'],options={'verify_exp':False,'verify_aud':False})
    assert claims==dict(typ='sociacl-oidc-attest-v1',**r['cred'],principal=r['principal'],iat=100,exp=200,nonce=r['nonce'])
    assert s.replay(out,out['fingerprint'],r['principal'],199)==out['attestation']
    for fp,principal,at in [('changed',r['principal'],101),(out['fingerprint'],'other',101),(out['fingerprint'],r['principal'],200)]:
        with pytest.raises(s.FirstLinkRefused):s.replay(out,fp,principal,at)


def test_foreign_stale_missing_fresh_auth_and_tenant_mapper_refuse():
    r,b,j,k,signer,token,c=fixture()
    for changes in [dict(sub='other'),dict(iss='https://other.example'),dict(aud='other'),dict(azp='other'),dict(nonce='other'),dict(auth_time=99),dict(iat=99),dict(exp=101),dict(nbf=102),dict(auth_time=True)]:
        with pytest.raises(s.FirstLinkRefused):s.issue(r,token(c|changes),b,j,k,signer,101)
    missing=dict(c);missing.pop('auth_time')
    with pytest.raises(s.FirstLinkRefused):s.issue(r,token(missing),b,j,k,signer,101)
    with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),b|{'tenantClaim':'tid'},j,k,signer,101)
    assert s.issue(r,token(c|{'tid':b['tenant']}),b|{'tenantClaim':'tid'},j,k,signer,101)


def test_native_record_and_trust_mutations_refuse():
    r,b,j,k,signer,token,c=fixture()
    for changes in [dict(seq=0),dict(principal='bad'),dict(keySig='bad'),dict(nonce='changed123'),dict(issuedAt=99),dict(attest='already-signed'),dict(v=True)]:
        with pytest.raises(s.FirstLinkRefused):s.issue(r|changes,token(),b,j,k,signer,101)
    for binding in [b|{'sequence':1},b|{'expiresAt':101},b|{'subject':'other'},b|{'tenant':'invalid'}]:
        with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),binding,j,k,signer,101)
    for signer_meta in [k|{'notAfter':101},k|{'notBefore':101},k|{'kid':''}]:
        with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),b,j,signer_meta,signer,101)
    for key_changes in [dict(notAfter=101),dict(notBefore=102),dict(kid='rotated'),dict(key_ops=['sign'])]:
        bad=copy.deepcopy(j);bad['keys'][0].update(key_changes)
        with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),b,bad,k,signer,101)
    with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),b,j,k,signer,220)


def test_provider_authorization_window_bounds_attestation_and_original_retry():
    r,b,j,k,signer,token,c=fixture();j['keys'][0]['notAfter']=102
    out=s.issue(r,token(),b,j,k,signer,101)
    assert out['expiresAt']==102
    claims=jwt.decode(out['attestation'],signer.public_key(),algorithms=['ES256'],options={'verify_exp':False,'verify_aud':False})
    assert claims['exp']==102
    with pytest.raises(s.FirstLinkRefused):s.replay(out,out['fingerprint'],r['principal'],102)
    j['keys'][0]['notAfter']=200;j['keys'][0]['notBefore']=101
    with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),b,j,k,signer,101)
