"""Real Auth/User HTTP acceptance on a reconciled disposable historical database.

Images must already be qualified and available locally. This never deploys,
publishes, selects a shared database, or configures a provider operation.
"""
from __future__ import annotations
import argparse
import importlib.util
import inspect
import hashlib
import zipfile
import json
from pathlib import Path
import runpy
import sys
import uuid

import docker
import httpx
from sqlalchemy import create_engine, text

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_auth', ROOT/'scripts/check-container.py')
native = importlib.util.module_from_spec(spec); sys.modules[spec.name] = native; spec.loader.exec_module(native)


def verify_runtime(container, package, wheel):
    with zipfile.ZipFile(wheel) as archive:
        expected={n:hashlib.sha256(archive.read(n)).hexdigest() for n in archive.namelist() if n.startswith(package+'/')}
    assert expected, 'Runtime wheel has no selected package'
    code=("import hashlib,json,importlib;from pathlib import Path;"
        +"p="+repr(package)+";r=Path(importlib.import_module(p).__file__).parent;"
        +"print('RUNTIME_PROOF='+json.dumps({p+'/'+str(f.relative_to(r)):hashlib.sha256(f.read_bytes()).hexdigest() for f in r.rglob('*') if f.is_file() and '__pycache__' not in f.parts and f.suffix!='.pyc'}))")
    result=container.exec_run(['python','-I','-c',code]);assert result.exit_code==0,'Installed runtime inspection failed'
    actual=json.loads(next(line.removeprefix('RUNTIME_PROOF=') for line in result.output.decode().splitlines() if line.startswith('RUNTIME_PROOF=')))
    extra=set(actual)-set(expected)
    allowed={n for n in extra if package=='auth_service' and (n=='auth_service/migrate.py' or n.startswith('auth_service/migrations/'))}
    assert extra==allowed and all(actual.get(n)==h for n,h in expected.items()), 'Installed runtime differs from qualified wheel'
    return {'wheel_sha256':hashlib.sha256(wheel.read_bytes()).hexdigest(),'files':len(expected),'image_local_schema_files':sorted(allowed)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('auth-image','auth-revision','owner-image','owner-revision'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--auth-wheel',type=Path,required=True)
    parser.add_argument('--owner-wheel',type=Path,required=True)
    args = parser.parse_args()
    client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
    auth_image, owner_image = client.images.get(args.auth_image), client.images.get(args.owner_image)
    for image, revision in ((auth_image,args.auth_revision),(owner_image,args.owner_revision)):
        assert image.attrs['Config']['User']=='65532:65532'
        assert image.attrs['Config']['Labels']['org.opencontainers.image.revision']==revision
    # The package lane installs this digest-verified, source-pinned owner fixture.
    # It supplies operator reconciliation only; HTTP runs the separate owner image.
    import subprocess
    subprocess.run([__import__('sys').executable,str(ROOT/'scripts/verify_identity_owner_fixture.py')],check=True,stdout=subprocess.DEVNULL)
    from user_service.reconcile_identity_rls import reconcile
    import user_service.reconcile_identity_rls as reconciliation_module
    fixture_manifest=json.loads((ROOT/'tests_artifacts/identity-owner/manifest.json').read_text())
    with zipfile.ZipFile(ROOT/'tests_artifacts/identity-owner'/fixture_manifest['wheel']) as fixture:
        assert Path(reconciliation_module.__file__).read_bytes()==fixture.read('user_service/reconcile_identity_rls.py'), 'Installed reconciliation tool differs from verified owner fixture' 
    history = runpy.run_path(str(ROOT/'tests/historical_db_fixture.py'))
    from controlplane_db.migrations import upgrade
    from controlplane_events.inbox import INBOX_DDL
    from controlplane_events.outbox import OUTBOX_DDL
    identity = uuid.uuid4().hex
    password = uuid.uuid4().hex+uuid.uuid4().hex
    credential = uuid.uuid4().hex+uuid.uuid4().hex
    network = client.networks.create('auth-owner-runtime-'+identity)
    containers=[]; engine=None; checks=[]
    def start(image,name,*,environment=None,command=None,port=None):
        c=client.containers.run(image,name=name,network=network.name,detach=True,environment=environment,command=command,
            ports={str(port)+'/tcp':('127.0.0.1',None)} if port else {})
        containers.append(c);return c
    def endpoint(c,port):
        c.reload();return 'http://127.0.0.1:'+c.attrs['NetworkSettings']['Ports'][str(port)+'/tcp'][0]['HostPort']
    try:
        db_name='auth-owner-db-'+identity
        db=start(native.POSTGRES_IMAGE,db_name,environment={'POSTGRES_USER':'fixture','POSTGRES_PASSWORD':password,'POSTGRES_DB':'users'},port=5432)
        native.wait(lambda:db.exec_run(['pg_isready','-h','127.0.0.1','-U','fixture','-d','users']).exit_code==0)
        db.reload();port=db.attrs['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
        url=f'postgresql+psycopg://fixture:{password}@127.0.0.1:{port}/users'
        upgrade(url,chains=['platform','events'])
        engine=create_engine(url)
        with engine.begin() as cx:
            policy=reconcile(cx,apply=True)
            assert policy['status']=='reconciled' and policy['changed']==16
            assert reconcile(cx,apply=True)['status']=='current'
            cx.exec_driver_sql(OUTBOX_DDL);cx.exec_driver_sql(INBOX_DDL)
            cx.exec_driver_sql(f"CREATE ROLE user_reader LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS")
            cx.exec_driver_sql('GRANT USAGE ON SCHEMA public TO user_reader')
            cx.exec_driver_sql('GRANT SELECT ON users,roles,tenants,groups,user_group_memberships,operator_bans TO user_reader')
            cx.exec_driver_sql('GRANT SELECT,INSERT,UPDATE,DELETE ON service_outbox,event_inbox TO user_reader')
        checks.append('Immutable historical identity policies reconciled atomically and replayed before application startup')
        issuer_name='auth-owner-issuer-'+identity
        issuer=start(native.KEYCLOAK_IMAGE,issuer_name,environment={'KC_BOOTSTRAP_ADMIN_USERNAME':'fixture-admin','KC_BOOTSTRAP_ADMIN_PASSWORD':password},command=['start-dev','--http-port=8080'],port=8080)
        issuer_url=endpoint(issuer,8080)
        with httpx.Client(timeout=20,trust_env=False) as http:
            native.wait(lambda:http.get(issuer_url+'/realms/master/.well-known/openid-configuration').status_code==200)
            def admin_headers():
                r=http.post(issuer_url+'/realms/master/protocol/openid-connect/token',data={'grant_type':'password','client_id':'admin-cli','username':'fixture-admin','password':password});r.raise_for_status();return {'Authorization':'Bearer '+r.json()['access_token']}
            admin=admin_headers();realm='fixture-'+identity;admin_url=issuer_url+'/admin/realms/'+realm
            assert http.post(issuer_url+'/admin/realms',headers=admin,json={'realm':realm,'enabled':True}).status_code==201
            mappers=[{'name':'audience','protocol':'openid-connect','protocolMapper':'oidc-audience-mapper','config':{'included.client.audience':'controlplane-frontend','access.token.claim':'true'}},
                {'name':'auth-time','protocol':'openid-connect','protocolMapper':'oidc-usersessionmodel-note-mapper','config':{'user.session.note':'AUTH_TIME','claim.name':'auth_time','jsonType.label':'long','access.token.claim':'true','introspection.token.claim':'true'}},
                {'name':'terms','protocol':'openid-connect','protocolMapper':'oidc-hardcoded-claim-mapper','config':{'claim.name':'terms_and_conditions','claim.value':'1700000000','jsonType.label':'String','access.token.claim':'true'}}]
            assert http.post(admin_url+'/clients',headers=admin,json={'clientId':'controlplane-frontend','enabled':True,'publicClient':True,'standardFlowEnabled':True,'redirectUris':['http://127.0.0.1/fixture/callback'],'attributes':{'pkce.code.challenge.method':'S256'},'protocolMappers':mappers}).status_code==201
            assert http.post(admin_url+'/clients',headers=admin,json={'clientId':'fixture-introspection','enabled':True,'publicClient':False,'secret':password}).status_code==201
            assert http.post(admin_url+'/users',headers=admin,json={'username':'fixture-human','enabled':True,'emailVerified':True,'email':'fixture@example.invalid','firstName':'Fixture','lastName':'Human','credentials':[{'type':'password','value':password,'temporary':False}]}).status_code==201
            subject=http.get(admin_url+'/users?username=fixture-human',headers=admin).json()[0]['id']
            browser=start(auth_image.id,'auth-owner-browser-'+identity,command=['python','-c','import time;time.sleep(1200)'])
            code=('import os,uuid,hashlib,base64,httpx\nfrom html.parser import HTMLParser\nfrom urllib.parse import urlsplit,parse_qs\n'+inspect.getsource(native.LoginForm)+'\n'+inspect.getsource(native.browser_token)+"\nwith httpx.Client(timeout=20,trust_env=False,follow_redirects=False) as c:\n print('FIXTURE_TOKEN='+browser_token(c,os.environ['ISSUER'],os.environ['REALM'],os.environ['PASSWORD']))")
            result=browser.exec_run(['python','-c',code],environment={'ISSUER':f'http://{issuer_name}:8080','REALM':realm,'PASSWORD':password})
            assert result.exit_code==0,'Native PKCE browser login failed'
            token=next(x.removeprefix('FIXTURE_TOKEN=') for x in result.output.decode().splitlines() if x.startswith('FIXTURE_TOKEN='))
            tenant,other,member,role=(uuid.uuid4() for _ in range(4))
            with engine.begin() as cx:
                for t in (tenant,other):cx.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'),{'id':t,'name':str(t)})
                cx.execute(text("INSERT INTO roles(id,tenant_id,name,permissions) VALUES(:id,:tenant,'host','[]'::jsonb)"),{'id':role,'tenant':tenant})
                cx.execute(text("INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active,role_id) VALUES(:id,:tenant,:sub,'fixture@example.invalid','Fixture','Human','unspecified',true,:role)"),{'id':member,'tenant':tenant,'sub':subject,'role':role})
            issuer_address=f'http://{issuer_name}:8080/realms/{realm}'
            common={'FASTAPI_ENV':'test','KEYCLOAK_ISSUER':issuer_address,'KEYCLOAK_JWKS_URL':issuer_address+'/protocol/openid-connect/certs','KEYCLOAK_CLIENT_ID':'fixture-introspection','KEYCLOAK_CLIENT_SECRET':password,'KEYCLOAK_ALLOWED_CLIENT_IDS':'controlplane-frontend','KEYCLOAK_ALLOWED_AUDIENCES':'controlplane-frontend','API_KEY_EXCHANGE_JWT_SECRET':uuid.uuid4().hex+uuid.uuid4().hex,'ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED':'false','AUTH_IDENTITY_OWNER_TOKEN':credential}
            owner_name='auth-real-owner-'+identity
            owner=start(owner_image.id,owner_name,environment={**common,'DATABASE_URL':f'postgresql+asyncpg://user_reader:{password}@{db_name}:5432/users','SERVICE_NAME':'user-service'},port=8000)
            owner_url=endpoint(owner,8000)
            native.wait(lambda:http.get(owner_url+'/api/v1/health/').status_code==200)
            assert http.get(owner_url+'/version').json()['git_sha']==args.owner_revision
            owner_bytes=verify_runtime(owner,'user_service',args.owner_wheel)
            assert http.post(owner_url+'/api/v1/internal/identity/session-member',json={'subject':subject,'tenant_id':str(tenant)}).status_code==401
            checks.append('Actual qualified user application runs with restricted historical role and rejects anonymous identity commands')
            # Auth owns a separate schema and cannot see the historical owner tables.
            with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as cx:
                cx.exec_driver_sql('CREATE DATABASE auth')
            provision=db.exec_run(['psql','-U','fixture','-d','auth','-v','ON_ERROR_STOP=1','-c',f"CREATE ROLE auth_owner LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS; CREATE SCHEMA auth_service AUTHORIZATION auth_owner; ALTER ROLE auth_owner SET search_path TO auth_service;"])
            assert provision.exit_code==0,'Auth owner provisioning failed'
            auth_db=f'postgresql+asyncpg://auth_owner:{password}@{db_name}:5432/auth'
            migrated=start(auth_image.id,'auth-owner-migrate-'+identity,command=['python','-c',"import os,tempfile,subprocess; p=tempfile.NamedTemporaryFile(mode='w');p.write(os.environ['DATABASE_URL']);p.flush();subprocess.run(['python','-m','auth_service.migrate','--database-url-file',p.name],check=True)"],environment={'DATABASE_URL':auth_db})
            assert migrated.wait(timeout=60)['StatusCode']==0,'Auth migration failed'
            contexts={};auths={}
            for mode in ('jwt','introspection'):
                app=start(auth_image.id,'paired-auth-'+mode+'-'+identity,environment={**common,'DATABASE_URL':auth_db,'SERVICE_NAME':'auth-service','AUTH_TOKEN_VALIDATION_MODE':mode,'AUTH_CONNECT_INTROSPECTION_CLIENT_ID':'fixture-introspection','AUTH_CONNECT_INTROSPECTION_CLIENT_SECRET':password,'AUTH_IDENTITY_OWNER_URL':f'http://{owner_name}:8000'},port=8000)
                url=endpoint(app,8000);native.wait(lambda:http.get(url+'/api/v1/health/').status_code==200)
                assert http.get(url+'/version').json()['git_sha']==args.auth_revision
                auth_bytes=verify_runtime(app,'auth_service',args.auth_wheel)
                headers={'Authorization':'Bearer '+token}
                switched=http.post(url+'/auth/switch-tenant',headers=headers,json={'tenant_id':str(tenant)})
                assert switched.status_code==200, switched.text
                contexts[mode]={**headers,'Authorization':'Bearer '+switched.json()['access_token'],'X-Auth-Session-Token':token,'X-Tenant-ID':str(tenant)}
                for path in ('connect-session-context','verification-context'):
                    facts=http.get(url+'/auth/'+path,headers=contexts[mode]);assert facts.status_code==200,facts.text
                    assert facts.json()['member_id']==str(member) and facts.json()['second_factor_at'] is None
                assert http.post(url+'/auth/switch-tenant',headers=headers,json={'tenant_id':str(other)}).status_code==403
                assert http.post(url+'/auth/hypermesh-smoke/session',headers=headers).status_code==404
                auths[mode]=url
                checks.append(mode+': real owner switch and session facts; cross-tenant denial; smoke disabled; no invented MFA')
            with engine.begin() as cx:
                cx.execute(text("INSERT INTO operator_bans(id,tenant_id,subject_kind,subject_id,reason,created_by,created_at) VALUES(:id,:tenant,'user',:member,'fixture','fixture',now())"),{'id':uuid.uuid4(),'tenant':tenant,'member':member})
            for mode,url in auths.items():
                assert http.post(url+'/auth/switch-tenant',headers={'Authorization':'Bearer '+token},json={'tenant_id':str(tenant)}).status_code==403
                for path in ('connect-session-context','verification-context'):
                    denied=http.get(url+'/auth/'+path,headers=contexts[mode]);assert denied.status_code==403 and denied.json()['code']=='membership_revoked'
            checks.append('Durable owner ban revokes both real Auth modes immediately without a local cache')
            with engine.begin() as cx:cx.execute(text('UPDATE operator_bans SET lifted_at=now() WHERE subject_id=:member'),{'member':member})
            for mode,url in auths.items():
                assert http.get(url+'/auth/connect-session-context',headers=contexts[mode]).status_code==200
            checks.append('Lifting the durable ban restores real owner membership without restarting either service')
            owner.stop(timeout=2)
            for mode,url in auths.items():
                unavailable=http.post(url+'/auth/switch-tenant',headers={'Authorization':'Bearer '+token},json={'tenant_id':str(tenant)})
                assert unavailable.status_code==503 and unavailable.headers['cache-control']=='no-store'
                for path in ('connect-session-context','verification-context'):
                    unavailable=http.get(url+'/auth/'+path,headers=contexts[mode]);assert unavailable.status_code==503 and 'membership_revoked' not in unavailable.text
            checks.append('Real owner outage refuses switching and session facts in both modes without false revocation')
            assert http.post(admin_url+'/users/'+subject+'/logout',headers=admin_headers()).status_code==204
            for mode,url in auths.items():
                ended=http.get(url+'/auth/connect-session-context',headers=contexts[mode]);assert ended.status_code==403 and 'membership_revoked' not in ended.text
            checks.append('Issuer logout is rejected before membership even while real owner is unavailable')
        args.evidence.parent.mkdir(parents=True,exist_ok=True)
        args.evidence.write_text(json.dumps({'schema_version':1,'scope':'disposable actual-owner HTTP runtime; not fleet deployment','auth_revision':args.auth_revision,'auth_image_id':auth_image.id,'owner_revision':args.owner_revision,'owner_image_id':owner_image.id,'historical_manifest':json.loads((ROOT/'tests/historical_db/manifest.json').read_text()),'reconciliation':policy,'reconciliation_fixture':fixture_manifest,'auth_runtime':auth_bytes,'owner_runtime':owner_bytes,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'checks':checks},indent=2)+'\n')
        print(str(len(checks))+' real owner/Auth runtime acceptance groups passed')
    finally:
        if engine is not None:engine.dispose()
        for c in reversed(containers):c.remove(force=True,v=True)
        network.remove()


if __name__=='__main__':main()
