"""Pure proof-attempt state units; no provider, native crypto or database."""
import copy
import unittest
from urllib.parse import parse_qs, urlsplit
try:
    from auth_service import linked_oidc_state as s
except ModuleNotFoundError:
    # A minimal local interpreter can run this pure module without installing
    # the service. CI imports the real package and measures its coverage.
    import importlib.util
    from pathlib import Path
    package = importlib.util.find_spec('auth_service')
    spec = importlib.util.spec_from_file_location('linked_oidc_state_units', Path(package.origin).parent / 'linked_oidc_state.py')
    s = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(s)

class LinkedProofTests(unittest.TestCase):
    def setUp(self):
        self.provider=dict(origin='https://test.s3r.ch',issuer='https://issuer.example',tenant='tenant',
            tenantClaim='tid',clientId='s3rch',authorizationEndpoint='https://issuer.example/auth',
            redirectUri='https://test.s3r.ch/api/identity/linked/callback')
        self.challenge=dict(token='signed-original',id='i'*43,issuedAt=100,expiresAt=200,
            origin=self.provider['origin'],credential=dict(kind='oidc',iss=self.provider['issuer'],tenant='tenant',sub='person'))
        self.run={'run':'original','generation':1}
        self.row=s.begin(self.challenge,self.provider,now=100,state='s'*43,verifier='v'*43,run=self.run)
    def claim(self,**kw):return s.claim_exchange(self.row,self.provider,self.challenge,**(dict(now=101,state='s'*43,run=self.run)|kw))
    def test_url_keeps_challenge_nonce_and_pkce_server_owned(self):
        q=parse_qs(urlsplit(s.authorization_url(self.row,self.provider)).query)
        self.assertEqual(q['nonce'],['i'*43]);self.assertEqual(q['code_challenge_method'],['S256'])
        self.assertEqual(q['response_mode'],['form_post']);self.assertNotIn('token',q)
        self.assertNotIn('verifier',q);self.assertNotEqual(q['code_challenge'],['v'*43])
    def test_one_exchange_and_exact_lost_response_readback(self):
        self.assertEqual(self.claim(),'v'*43)
        with self.assertRaises(s.LinkedProofRefused):self.claim()
        s.complete(self.row,self.provider,self.challenge,sealed_proof='opaque',now=102,run=self.run)
        for _ in range(2):self.assertEqual(s.result(self.row,self.provider,self.challenge,now=103,run=self.run),'opaque')
        self.assertEqual(self.row['verifier'],'')
    def test_cancel_blocks_inflight_completion_and_readback(self):
        self.claim();s.cancel(self.row)
        with self.assertRaises(s.LinkedProofRefused):s.complete(self.row,self.provider,self.challenge,sealed_proof='opaque',now=102,run=self.run)
        with self.assertRaises(s.LinkedProofRefused):s.result(self.row,self.provider,self.challenge,now=102,run=self.run)
    def test_swapped_state_original_run_scope_and_expiry_refuse(self):
        for kw in ({'state':'x'*43},{'now':200},{'run':{'run':'replacement','generation':1}}):
            with self.assertRaises(s.LinkedProofRefused):self.claim(**kw)
        for field,value in [('token','replacement'),('origin','https://foreign.example')]:
            changed=dict(self.challenge,**{field:value})
            with self.assertRaises(s.LinkedProofRefused):s.bound(self.row,self.provider,changed,101,self.run)
        with self.assertRaises(s.LinkedProofRefused):s.bound(self.row,dict(self.provider,clientId='other'),self.challenge,101,self.run)
        self.assertEqual(self.row['phase'],'pending')
    def test_fresh_signature_verified_claim_constraints(self):
        claims=dict(iss=self.provider['issuer'],sub='person',tid='tenant',aud='s3rch',nonce='i'*43,iat=100,auth_time=100,exp=200)
        s.verify_claims(claims,self.row,self.provider,101)
        for key,value in [('sub','other'),('tid','other'),('aud',['s3rch','other']),('nonce','x'*43),('iat',True),('auth_time',99),('exp',101),('azp','other')]:
            with self.assertRaises(s.LinkedProofRefused):s.verify_claims(dict(claims,**{key:value}),self.row,self.provider,101)
    def test_snapshot_does_not_alias_inputs(self):
        self.run['generation']=2;self.challenge['credential']['sub']='changed'
        self.assertEqual(self.row['run']['generation'],1)
        self.assertEqual(self.row['challenge']['credential']['sub'],'person')

if __name__=='__main__':unittest.main()
