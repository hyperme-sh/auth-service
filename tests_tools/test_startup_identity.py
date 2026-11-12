import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

ROOT=Path(__file__).resolve().parents[1]
# Isolate these pure unit modules from the package's unrelated application imports.
import importlib.util
import types
package = types.ModuleType('_auth_startup_unit')
package.__path__ = [str(ROOT/'src/auth_service')]
sys.modules[package.__name__] = package
spec = importlib.util.spec_from_file_location('_auth_startup_unit.startup_identity', ROOT/'src/auth_service/startup_identity.py')
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)
from _auth_startup_unit._startup_contract import fingerprint


class StartupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.config=json.loads(Path(__file__).with_name('startup-identity.json').read_text())
        self.person={'schema_version':1,'mapping_sha256':fingerprint(self.config),'status':'reconciled',
            'person_id':'00000000-0000-4000-8000-000000000110','tenant_id':self.config['owner']['tenant_id'],
            'network_id':self.config['owner']['network_id'],'broker_subject':None,
            'organizations':[{'slug':slug,'id':o['organization_id'],'tenant_id':o['tenant_id'],'roles':o['roles']} for slug,o in sorted(self.config['binding']['organizations'].items())]}
        self.claims={'iss':self.config['owner']['broker']['issuer'],'aud':self.config['owner']['broker']['audience'],'azp':self.config['owner']['broker']['audience'],
            'sub':self.person['person_id'],'login_provider':'startup-microsoft','entra_tenant_id':self.config['binding']['entra']['tenant_id'],
            'entra_object_id':self.config['binding']['entra']['object_id'],'email':self.config['owner']['profile']['email']}

    async def test_bind_replays_without_session_privileges(self):
        for subject in [None,self.person['person_id']]:
            person=dict(self.person,broker_subject=subject)
            bound={'mapping_sha256':fingerprint(self.config),'person_id':person['person_id'],
                'broker_subject':person['person_id'],'status':'bound'}
            with patch.object(identity,'owner',AsyncMock(side_effect=[person,bound])) as owner:
                result=await identity.reconcile(self.config)
                self.assertEqual(result['permissions'],[])
                self.assertEqual(owner.await_args_list[1].kwargs,{'subject':person['person_id']})

    async def test_verified_login_resolves_only_existing_subject(self):
        person=dict(self.person,broker_subject=self.claims['sub'])
        with patch.object(identity,'owner',AsyncMock(return_value=person)) as owner:
            result=await identity.resolve(self.config,self.claims)
            self.assertEqual(result['person_id'],person['person_id'])
            self.assertEqual(result['permissions'],[])
            owner.assert_awaited_once_with('status',self.config)

    async def test_wrong_tuple_issuer_audience_and_missing_claim_refuse_same_email(self):
        for field in ['iss','aud','azp','entra_tenant_id','entra_object_id','login_provider']:
            for missing in ([False] if field == 'azp' else [False,True]):
                claims=dict(self.claims)
                if missing: claims.pop(field)
                else: claims[field]='attacker'
                with self.subTest(field=field,missing=missing),patch.object(identity,'owner',AsyncMock()) as owner:
                    with self.assertRaises(ValueError): await identity.resolve(self.config,claims)
                    owner.assert_not_called()

    async def test_wrong_subject_and_session_claims_never_bind(self):
        for claims in [dict(self.claims,sub='different'),dict(self.claims,spanopticon_auth='tenant_session')]:
            with patch.object(identity,'owner',AsyncMock(return_value=dict(self.person,broker_subject=self.claims['sub']))) as owner:
                with self.assertRaises(ValueError): await identity.resolve(self.config,claims)
                self.assertTrue(all(call.args[0]=='status' for call in owner.await_args_list))

    async def test_conflicting_owner_mapping_stops_before_write(self):
        for key,value in [('mapping_sha256','0'*64),('tenant_id','other'),('person_id','not-uuid'),('organizations',[])]:
            with patch.object(identity,'owner',AsyncMock(return_value=dict(self.person,**{key:value}))) as owner:
                with self.assertRaises(ValueError): await identity.reconcile(self.config)
                self.assertEqual(owner.await_count,1)

    async def test_missing_binding_does_not_create_during_login(self):
        with patch.object(identity,'owner',AsyncMock(return_value=self.person)) as owner:
            with self.assertRaises(ValueError): await identity.resolve(self.config,self.claims)
            self.assertEqual(owner.await_count,1)

    def test_exact_additive_contract_copy(self):
        source=json.loads((ROOT/'src/auth_service/startup_contract_source.json').read_text())
        self.assertEqual(source['sha256'],hashlib.sha256((ROOT/'src/auth_service/_startup_contract.py').read_bytes()).hexdigest())
