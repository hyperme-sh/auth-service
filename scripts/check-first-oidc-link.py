"""CI-only native ACL acceptance for Auth first-link candidate output."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
import jwt
from auth_service import first_oidc_link as s

if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Native contract requires CI')
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('first_link_fixture',root/'tests/test_first_oidc_link.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
acl=root/'acl-first-link-source/admission'
f=json.loads((acl/'fixture.json').read_text());now=f['now']
r,b,j,k,signer,token,claims=module.fixture(now)
assert r['principal']==f['genesis']
b['issuer']=f['pinnedIss'][0];r['cred']['iss']=b['issuer'];claims['iss']=b['issuer']
x,y=utils.decode_dss_signature(ec.derive_private_key(1,ec.SECP256R1()).sign(s.signing_bytes(r),ec.ECDSA(hashes.SHA256())))
r['keySig']=module.enc(x.to_bytes(32)+y.to_bytes(32))
out=s.issue(r,token(claims),b,j,k,signer,now+1)
record=r|{'attest':out['attestation']}
public=json.loads(jwt.algorithms.ECAlgorithm.to_jwk(signer.public_key()))|k|{'alg':'ES256','use':'sig','key_ops':['verify']}
trust={name:f[name] for name in ('policy','pinnedIss')};trust['jwks']={'keys':f['jwks']['keys']+[public]}
payload=dict(principal=f['genesis'],trust=trust,now=now+1,genesis=f['binding'],entries=[],record=record)
def accepted(value):
    return subprocess.run(['node',str(acl/'verify.mjs')],input=json.dumps(value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15).returncode==0
assert accepted(payload),'native ACL refused Auth output'
assert not accepted(payload|{'entries':[record]}),'duplicate admission accepted'
for bad in [record|{'keySig':'bad'},record|{'nonce':'b'*64},record|{'cred':record['cred']|{'sub':'other'}},record|{'seq':0}]:
    assert not accepted(payload|{'record':bad}),'mutated native record accepted'
assert not accepted(payload|{'trust':trust|{'jwks':{'keys':f['jwks']['keys']}}}),'unknown attestation signer accepted'
assert not accepted(payload|{'now':out['expiresAt']}),'expired attestation accepted'
print('Native ACL accepts Auth first-link output and refuses duplicate, mutation, unknown signer and expiry')
