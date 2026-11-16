"""Distinct native genesis signatures and provider nonce; native CI only."""
import copy
import importlib.util
from pathlib import Path
import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec,utils
from auth_service import first_genesis as s
spec=importlib.util.spec_from_file_location('genesis_oidc_fixture',Path(__file__).with_name('test_first_oidc_link.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)


def fixture(now=100,**changes):
    _,b,j,k,signer,token,claims=f.fixture(now,**changes)
    encryption=ec.derive_private_key(2,ec.SECP256R1()).public_key().public_numbers()
    b=b|{'epub':f.enc(encryption.x.to_bytes(32))+'.'+f.enc(encryption.y.to_bytes(32))}
    r=dict(v=1,kind='genesis-epub',principal=b['principal'],epub=b['epub'],issuedAt=now,keySig='',attest='')
    x,y=utils.decode_dss_signature(ec.derive_private_key(1,ec.SECP256R1()).sign(s.signing_bytes(r),ec.ECDSA(hashes.SHA256())))
    r['keySig']=f.enc(x.to_bytes(32)+y.to_bytes(32));claims['nonce']=s.request_nonce(r,b)
    return r,b,j,k,signer,lambda c=claims:token(c),claims


def test_distinct_claims_nonce_and_exact_retry():
    r,b,j,k,signer,token,c=fixture();out=s.issue(r,token(),b,j,k,signer,101)
    claims=jwt.decode(out['attestation'],signer.public_key(),algorithms=['ES256'],options={'verify_exp':False})
    assert claims==dict(typ='sociacl-genesis-epub-attest-v1',principal=r['principal'],epub=r['epub'],iat=100,exp=200)
    assert s.replay(out,out['fingerprint'],r['principal'],199)==out['attestation']
    with pytest.raises(s.FirstLinkRefused):s.replay(out,out['fingerprint'],r['principal'],200)
    for key in ('issuer','tenant','subject','clientId'):
        assert s.request_nonce(r,b|{key:b[key]+'x'})!=c['nonce']
    assert s.request_nonce(r,b|{'expiresAt':b['expiresAt']-1})!=c['nonce']
    assert s.request_nonce(r|{'keySig':r['keySig']+'x'},b)!=c['nonce']
    assert s.request_nonce(r|{'epub':r['principal']},b)!=c['nonce']
    assert s.issue(r,token(),b,j|{'keys':[j['keys'][0]|{'notAfter':150}]},k,signer,101)['expiresAt']==150


def test_request_provider_and_protected_binding_mutations_refuse():
    r,b,j,k,signer,token,c=fixture()
    for record in [r|{'nonce':'extra'},r|{'sequence':0},r|{'v':True},r|{'kind':'oidc'},r|{'attest':'supplied'},
                   r|{'issuedAt':True},r|{'issuedAt':102},r|{'epub':r['principal']},r|{'keySig':'bad'},r|{'principal':'bad'}]:
        with pytest.raises(s.FirstLinkRefused):s.issue(record,token(),b,j,k,signer,101)
    for binding in [b|{'expiresAt':True},b|{'expiresAt':100},b|{'expiresAt':2**53},b|{'sequence':1},b|{'principal':'other'},
                    b|{'epub':'bad'},b|{'issuer':'http://other'},b|{'tenant':'bad'},b|{'subject':''},b|{'clientId':''},b|{'tenantClaim':True}]:
        with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),binding,j,k,signer,101)
    for change in [dict(nonce='different'),dict(sub='other'),dict(auth_time=99),dict(exp=100)]:
        with pytest.raises(s.FirstLinkRefused):s.issue(r,token(c|change),b,j,k,signer,101)
    for meta in [k|{'kid':''},k|{'notBefore':101},k|{'notAfter':101},k|{'notAfter':True}]:
        with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),b,j,meta,signer,101)
    with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),b,j,k,ec.generate_private_key(ec.SECP384R1()),101)
    with pytest.raises(s.FirstLinkRefused):s.issue(r,token(),b,j,k,signer,220)
