"""Qualify the standalone image using disposable PostgreSQL and Keycloak only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid

import docker
import httpx
import jwt

ROOT = Path(__file__).resolve().parents[1]
POSTGRES_IMAGE = 'postgres:16-alpine@sha256:20edbde7749f822887a1a022ad526fde0a47d6b2be9a8364433605cf65099416'
KEYCLOAK_IMAGE = 'quay.io/keycloak/keycloak@sha256:8d44614c74798322c4e07fbe0ecb15cfbb5879d69b484628555f58ade06f0d8c'


def wait(check, *, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (httpx.TransportError, docker.errors.APIError):
            pass
        time.sleep(0.5)
    raise AssertionError('Disposable service did not become ready')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', help='Use an existing local image instead of building')
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    identity = uuid.uuid4().hex
    image = args.image or 'auth-container-qualification:' + identity
    client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
    client.ping()
    containers = []
    network = None
    checks = []
    built_here = False
    try:
        if not args.image:
            subprocess.run(['docker', 'build', '--build-arg', 'GIT_SHA=' + revision,
                            '-t', image, '.'], cwd=ROOT, check=True)
        built = client.images.get(image)
        built_here = not args.image
        assert built.attrs['Config']['User'] == '65532:65532'
        network = client.networks.create('auth-qualification-' + identity)

        def start(selected_image, *, name, environment=None, command=None, port=None):
            try:
                client.images.get(selected_image)
            except docker.errors.ImageNotFound:
                client.images.pull(selected_image)
            container = client.containers.run(selected_image, name=name,
                environment=environment, command=command, network=network.name,
                ports={str(port) + '/tcp': ('127.0.0.1', None)} if port else {}, detach=True)
            containers.append(container)
            return container

        def endpoint(container, port):
            container.reload()
            binding = container.attrs['NetworkSettings']['Ports'][str(port) + '/tcp'][0]
            assert binding['HostIp'] == '127.0.0.1'
            return 'http://127.0.0.1:' + binding['HostPort']

        password = uuid.uuid4().hex + uuid.uuid4().hex
        db_name, issuer_name = 'auth-db-' + identity, 'auth-issuer-' + identity
        db = start(POSTGRES_IMAGE, name=db_name,
            environment={'POSTGRES_USER': 'fixture', 'POSTGRES_PASSWORD': password, 'POSTGRES_DB': 'auth'})
        # The entrypoint's temporary init server accepts Unix sockets before
        # database creation finishes. Only the final server listens on TCP.
        wait(lambda: db.exec_run(['pg_isready', '-h', '127.0.0.1', '-U', 'fixture', '-d', 'auth']).exit_code == 0)
        owner_password = uuid.uuid4().hex + uuid.uuid4().hex
        provision = db.exec_run(['psql', '-U', 'fixture', '-d', 'auth', '-v', 'ON_ERROR_STOP=1', '-c',
            f"CREATE ROLE auth_owner LOGIN PASSWORD '{owner_password}' NOSUPERUSER NOBYPASSRLS; "
            "CREATE SCHEMA auth_service AUTHORIZATION auth_owner; "
            "ALTER ROLE auth_owner IN DATABASE auth SET search_path=auth_service; "
            "REVOKE ALL ON SCHEMA public FROM PUBLIC;"])
        assert provision.exit_code == 0, ('Disposable owner-role bootstrap failed: ' +
            provision.output.decode(errors='replace').replace(password, '[redacted]').replace(owner_password, '[redacted]'))
        database_url = f'postgresql+asyncpg://auth_owner:{owner_password}@{db_name}:5432/auth' 
        issuer = start(KEYCLOAK_IMAGE, name=issuer_name, port=8080,
            environment={'KC_BOOTSTRAP_ADMIN_USERNAME': 'fixture-admin', 'KC_BOOTSTRAP_ADMIN_PASSWORD': password},
            command=f'start-dev --hostname=http://{issuer_name}:8080 --hostname-strict=false')
        with httpx.Client(timeout=20, trust_env=False, follow_redirects=False) as http:
            issuer_url = endpoint(issuer, 8080)
            wait(lambda: http.get(issuer_url + '/realms/master/.well-known/openid-configuration').status_code == 200)
            response = http.post(issuer_url + '/realms/master/protocol/openid-connect/token', data={
                'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'fixture-admin', 'password': password})
            response.raise_for_status()
            admin = {'Authorization': 'Bearer ' + response.json()['access_token']}
            realm = 'fixture-' + identity
            assert http.post(issuer_url + '/admin/realms', headers=admin,
                             json={'realm': realm, 'enabled': True}).status_code == 201
            admin_url = issuer_url + '/admin/realms/' + realm
            for client_id, adult in (('controlplane-frontend', True), ('controlplane-mobile', False), ('hypermesh-host-setup', False)):
                mappers = [{'name': 'audience', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
                    'config': {'included.client.audience': client_id, 'access.token.claim': 'true'}}]
                if adult:
                    mappers.append({'name': 'fixture-adult', 'protocol': 'openid-connect',
                        'protocolMapper': 'oidc-hardcoded-claim-mapper', 'config': {
                            'claim.name': 'terms_and_conditions', 'claim.value': '1700000000',
                            'jsonType.label': 'String', 'access.token.claim': 'true'}})
                assert http.post(admin_url + '/clients', headers=admin, json={
                    'clientId': client_id, 'enabled': True, 'publicClient': True,
                    'standardFlowEnabled': False, 'directAccessGrantsEnabled': True,
                    'protocolMappers': mappers}).status_code == 201
            assert http.post(admin_url + '/clients', headers=admin, json={
                'clientId': 'fixture-introspection', 'enabled': True, 'publicClient': False,
                'secret': password, 'standardFlowEnabled': False, 'directAccessGrantsEnabled': False}).status_code == 201
            assert http.post(admin_url + '/users', headers=admin, json={
                'username': 'fixture-human', 'enabled': True, 'emailVerified': True,
                'email': 'fixture@example.invalid', 'firstName': 'Fixture', 'lastName': 'Human',
                'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}).status_code == 201
            subject = http.get(admin_url + '/users?username=fixture-human', headers=admin).json()[0]['id']
            tokens = {}
            for client_id in ('controlplane-frontend', 'controlplane-mobile', 'hypermesh-host-setup'):
                response = http.post(issuer_url + f'/realms/{realm}/protocol/openid-connect/token', data={
                    'grant_type': 'password', 'client_id': client_id, 'username': 'fixture-human', 'password': password})
                response.raise_for_status()
                tokens[client_id] = response.json()['access_token']
            env = {'DATABASE_URL': database_url, 'SERVICE_NAME': 'auth-service', 'FASTAPI_ENV': 'test',
                'KEYCLOAK_ISSUER': f'http://{issuer_name}:8080/realms/{realm}',
                'KEYCLOAK_JWKS_URL': f'http://{issuer_name}:8080/realms/{realm}/protocol/openid-connect/certs',
                'KEYCLOAK_CLIENT_ID': 'fixture-introspection', 'KEYCLOAK_CLIENT_SECRET': password,
                'KEYCLOAK_ALLOWED_CLIENT_IDS': ','.join(tokens),
                'KEYCLOAK_ALLOWED_AUDIENCES': ','.join(tokens),
                'API_KEY_EXCHANGE_JWT_SECRET': uuid.uuid4().hex + uuid.uuid4().hex,
                'ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED': 'false'}
            target_tenant, owner_member, owner_token = str(uuid.uuid4()), str(uuid.uuid4()), uuid.uuid4().hex
            owner_name = 'auth-host-owner-' + identity
            owner = start(image, name=owner_name,
                environment={'HOST_SETUP_FIXTURE_SUBJECT':subject, 'HOST_SETUP_FIXTURE_TENANT':target_tenant,
                    'HOST_SETUP_FIXTURE_MEMBER':owner_member, 'HOST_SETUP_FIXTURE_TOKEN':owner_token},
                command=['python','-c',(ROOT/'scripts/host-owner-fixture.py').read_text()])
            wait(lambda: owner.exec_run(['python','-c',"import socket; s=socket.create_connection(('127.0.0.1',8001),timeout=1); s.close()"]).exit_code==0)
            env.update(AUTH_IDENTITY_OWNER_URL='http://' + owner_name + ':8001', AUTH_IDENTITY_OWNER_TOKEN=owner_token)

            migration = start(image, name='auth-migrate-' + identity, environment=env,
                command=['python', '-c', '''import os
from sqlalchemy import create_engine, text
from importlib.resources import files
from controlplane_events.owner_schema import migrate
from controlplane_events.store import normalize_sync_url
engine=create_engine(normalize_sync_url(os.environ['DATABASE_URL']))
for _ in range(2):
    migrate(engine, revision='0001_owner_schema', ddl=files('auth_service').joinpath('migrations/0001.sql').read_text())
with engine.connect() as db:
    assert db.execute(text("SELECT to_regclass('users')")).scalar() is None
    assert db.execute(text("SELECT to_regclass('service_outbox')")).scalar() is not None
engine.dispose()
'''])
            assert migration.wait(timeout=45)['StatusCode'] == 0, migration.logs().decode()
            checks.append('Fresh image-local owner migration is idempotent and creates no user tables')
            runtime_probe = '''import importlib.metadata as m, json, os, pathlib, shutil
assert os.geteuid()!=0
assert not pathlib.Path('/app/src').exists() and not pathlib.Path('/app/tests').exists()
assert shutil.which('git') is None
assert not {'testcontainers','docker','uv'} & {d.metadata['Name'] for d in m.distributions()}
import auth_service.app
print(json.dumps({'uid':os.geteuid(),'auth_version':m.version('auth-service')}))
'''
            auth_urls = {}
            for mode in ('jwt', 'introspection'):
                auth = start(image, name='auth-' + mode + '-' + identity, port=8000,
                    environment={**env, 'AUTH_TOKEN_VALIDATION_MODE': mode})
                url = endpoint(auth, 8000)
                wait(lambda: http.get(url + '/api/v1/health/').status_code == 200)
                probe = auth.exec_run(['python', '-c', runtime_probe])
                assert probe.exit_code == 0, probe.output.decode()
                checks.append(mode + ': non-root installed runtime without checkout, fixture or build tools')
                version = http.get(url + '/version');assert version.status_code == 200
                expected_revision = built.attrs['Config']['Labels']['org.opencontainers.image.revision']
                assert version.json()['git_sha'] == expected_revision
                spec = http.get(url + '/openapi.json').json()
                assert {'/version', '/auth/me', '/auth/host-setup/session'} <= set(spec['paths'])
                checks.append(mode + ': health, version identity and native OpenAPI routes')
                for token, expected in ((None, 401), ('invalid-token', 401),
                    (tokens['controlplane-mobile'], 401), (tokens['hypermesh-host-setup'], 401),
                    (tokens['controlplane-frontend'], 200)):
                    headers = {'Authorization': 'Bearer ' + token} if token else {}
                    response = http.get(url + '/auth/me', headers=headers)
                    assert response.status_code == expected, (mode, expected, response.status_code, response.text)
                    if expected == 200:
                        assert response.json()['sub'] == subject
                checks.append(mode + ': native adult identity accepted; absent, invalid, unconfirmed and setup credentials rejected')
                response = http.get(url + '/auth/host-setup/me', headers={'Authorization': 'Bearer ' + tokens['hypermesh-host-setup']})
                assert response.status_code == 200 and response.json()['sub'] == subject
                response = http.get(url + '/auth/tenant', headers={'Authorization': 'Bearer ' + tokens['controlplane-frontend'], 'X-Tenant-ID': str(uuid.uuid4())})
                assert response.status_code == 403
                checks.append(mode + ': dedicated setup accepted and header-only tenant authority denied')
                setup_headers = {'Authorization':'Bearer ' + tokens['hypermesh-host-setup'], 'X-Tenant-ID':target_tenant}
                reply = http.post(url + '/auth/host-setup/session',headers=setup_headers,json={'tenant_id':target_tenant})
                assert reply.status_code == 200, reply.text
                setup = jwt.decode(reply.json()['access_token'],env['API_KEY_EXCHANGE_JWT_SECRET'],
                    algorithms=['HS256'],audience='hypermesh-host-setup',issuer='https://spanopticon.internal/host-setup')
                assert setup['sub']==subject and setup['tenant_id']==target_tenant and setup['purpose']=='host_setup'
                assert not {'permissions','realm_access','groups','spanopticon_auth'} & setup.keys()
                checks.append(mode + ': fresh auth-only schema mints only a purpose-bound setup token after owner HTTP grant')
                for owner_mode, expected in (('deny',403),('invalid',503)):
                    assert owner.exec_run(['python','-c',f"from pathlib import Path; Path('/tmp/owner-mode').write_text('{owner_mode}')"]).exit_code==0
                    reply=http.post(url+'/auth/host-setup/session',headers=setup_headers,json={'tenant_id':target_tenant})
                    assert reply.status_code==expected, (owner_mode,reply.status_code,reply.text)
                assert owner.exec_run(['python','-c',"from pathlib import Path; Path('/tmp/owner-mode').unlink()"]).exit_code==0
                reply=http.post(url+'/auth/host-setup/session',headers=setup_headers,json={'tenant_id':str(uuid.uuid4())})
                assert reply.status_code==403
                checks.append(mode + ': denied, malformed and mismatched host authority cannot mint a token')
                auth_urls[mode] = url
            owner.stop(timeout=2)
            for url in auth_urls.values():
                reply=http.post(url+'/auth/host-setup/session',headers={
                    'Authorization':'Bearer '+tokens['hypermesh-host-setup'],'X-Tenant-ID':target_tenant},json={'tenant_id':target_tenant})
                assert reply.status_code==503
            checks.append('Unavailable owner cannot reuse an earlier host grant in either auth mode')
            assert http.post(admin_url + '/users/' + subject + '/logout', headers=admin).status_code == 204
            response = http.get(auth_urls['introspection'] + '/auth/me', headers={'Authorization': 'Bearer ' + tokens['controlplane-frontend']})
            assert response.status_code == 401
            checks.append('Native logout makes introspected session inactive')
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps({'source_revision': revision, 'image_id': built.id,
            'image_revision': built.attrs['Config']['Labels']['org.opencontainers.image.revision'],
            'fixtures': {'postgres': POSTGRES_IMAGE, 'keycloak': KEYCLOAK_IMAGE}, 'checks': checks,
            'scope': 'Disposable auth container/issuer with an explicit owner HTTP fixture; actual owner SQL/RLS runs separately in package tests; no deployment or provider activation'}, indent=2)+'\n')
        print(f'{len(checks)} standalone container acceptance groups passed')
    finally:
        cleanup_errors = []
        for container in reversed(containers):
            try:
                container.remove(force=True, v=True)
            except docker.errors.APIError:
                cleanup_errors.append('container')
        if network is not None:
            try:
                network.remove()
            except docker.errors.APIError:
                cleanup_errors.append('network')
        if built_here:
            try:
                client.images.remove(image)
            except docker.errors.APIError:
                cleanup_errors.append('image')
        client.close()
        if cleanup_errors:
            raise RuntimeError('Task-owned fixture cleanup failed: ' + ', '.join(cleanup_errors))


if __name__ == '__main__':
    main()
