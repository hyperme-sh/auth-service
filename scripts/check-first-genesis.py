"""CI-only native ACL genesis enrollment and independent nonce contract."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec,utils
import jwt
from auth_service import first_genesis as s
if os.environ.get('GITHUB_ACTIONS')!='true':raise SystemExit('Native contract requires CI')
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('native_genesis_fixture',root/'tests/test_first_genesis.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
acl=root/'acl-first-link-source/admission';fixture=json.loads((acl/'fixture.json').read_text())
r,b,j,k,signer,token,_=m.fixture(fixture['now'])
result=s.issue(r,token(),b,j,k,signer,fixture['now']+1);genesis=r|{'attest':result['attestation']}
public=json.loads(jwt.algorithms.ECAlgorithm.to_jwk(signer.public_key()))|k|{'alg':'ES256','use':'sig','key_ops':['verify']}
trust={name:fixture[name] for name in ('policy','pinnedIss')};trust['jwks']={'keys':fixture['jwks']['keys']+[public]}
# Independent Node encoder: exact UTF-8 lengths and little-endian framing.
script="""import {readFileSync} from 'node:fs';import {createHash} from 'node:crypto';import {linkId} from 'sociacl-ids';
const {r,b,genesis}=JSON.parse(readFileSync(0,'utf8'));
const values=['auth-first-genesis-provider-v1','1','genesis-epub',r.principal,r.epub,String(r.issuedAt),r.keySig,'',b.issuer,b.tenant,b.subject,b.clientId,String(b.expiresAt)];
const framed=Buffer.concat(values.flatMap(value=>{const bytes=Buffer.from(value,'utf8'),size=Buffer.alloc(4);size.writeUInt32LE(bytes.length);return [size,bytes];}));
const id=linkId(genesis);if(!id.ok)throw Error(id.reason);console.log(JSON.stringify({nonce:createHash('sha256').update(framed).digest('hex'),id:id.value}));"""
independent=json.loads(subprocess.run(['node','--input-type=module','-e',script],cwd=acl,input=json.dumps(dict(r=r,b=b,genesis=genesis)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=15).stdout)
assert independent['nonce']==s.request_nonce(r,b)
grant=dict(authority='declared-auth-owner',nonce='a'*64,expires_at=fixture['now']+90)
message=s.lp(['acl-service-history-enrollment-v1',grant['authority'],r['principal'],grant['nonce'],str(grant['expires_at']),independent['id']])
x,y=utils.decode_dss_signature(ec.derive_private_key(1,ec.SECP256R1()).sign(message,ec.ECDSA(hashes.SHA256())))
signature=m.f.enc(x.to_bytes(32)+y.to_bytes(32))
payload=dict(principal=r['principal'],trust=trust,now=fixture['now']+1,genesis=genesis,entries=[],grant=grant,signature=signature)
def accepted(value):return subprocess.run(['node',str(acl/'verify.mjs')],input=json.dumps(value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15).returncode==0
assert accepted(payload),'native ACL refused generated genesis attestation'
for bad in [genesis|{'epub':r['principal']},genesis|{'nonce':'extra'},genesis|{'attest':'bad'},genesis|{'keySig':'bad'}]:
    assert not accepted(payload|{'genesis':bad})
assert not accepted(payload|{'signature':'bad'})
assert not accepted(payload|{'trust':trust|{'jwks':{'keys':fixture['jwks']['keys']}}})
print('Native ACL accepted distinct provider-verified genesis and refused mutations; nonce agrees with independent JS')
