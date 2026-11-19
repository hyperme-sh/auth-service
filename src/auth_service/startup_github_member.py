"""Resolve one configured TEST GitHub member after Keycloak and User checks."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
from time import time
from uuid import UUID

import jwt
from controlplane_api.config import settings
from controlplane_identity.account_lifecycle import require_open_account
from controlplane_identity.nightly import current_binding, require, require_original_run

from ._startup_contract import InvalidBinding, fields, identifier, read_private, sea_key, unique_object
from .claims import mfa_satisfied
from .nightly_runtime import verify_claims
from .session_membership import authorize_session_member

ISSUER = 'https://auth.test.hyperme.sh/realms/controlplane'
AUDIENCE = 's3rch-web'
JWKS = jwt.PyJWKClient(ISSUER + '/protocol/openid-connect/certs', timeout=5)


def configuration():
    path = os.environ.get('STARTUP_TEST_GITHUB_MEMBER_CONFIG_FILE')
    supplied = os.environ.get('STARTUP_TEST_GITHUB_MEMBER_CONFIG')
    if settings.keycloak_issuer != ISSUER or bool(path) == (supplied is not None):
        raise InvalidBinding()
    raw = read_private(Path(path)) if path else supplied.encode('utf-8')
    if not 1 <= len(raw) <= 16384:
        raise InvalidBinding()
    mapping = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
    fields(mapping, ('version', 'environment', 'tenant_id', 'network_id', 'broker', 'sea_public_key'))
    broker = mapping['broker']
    fields(broker, ('issuer', 'audience', 'subject', 'provider'))
    if (type(mapping['version']) is not int or mapping['version'] != 1
            or mapping['environment'] != 'test' or mapping['network_id'] != 'hyperme.sh'
            or (broker['issuer'], broker['audience'], broker['provider']) != (ISSUER, AUDIENCE, 'github')):
        raise InvalidBinding()
    identifier(mapping['tenant_id'])
    identifier(broker['subject'])
    sea_key(mapping['sea_public_key'])
    return mapping, hashlib.sha256(raw).hexdigest()


def verify_access_token(token):
    if len(token) > 16384:
        raise InvalidBinding()
    key = JWKS.get_signing_key_from_jwt(token)
    claims = jwt.decode(token, key.key, algorithms=['RS256'], issuer=ISSUER, audience=AUDIENCE,
                        options={'require': ['iat', 'exp', 'sub', 'iss', 'aud']})
    if (claims.get('typ') != 'Bearer' or claims.get('azp') != AUDIENCE
            or claims.get('login_provider') != 'github' or 'purpose' in claims
            or 'spanopticon_auth' in claims or not mfa_satisfied(claims)):
        raise InvalidBinding()
    require_open_account(claims)
    return claims


async def resolve(token):
    mapping, digest = configuration()
    claims = await verify_claims(await asyncio.to_thread(verify_access_token, token))
    require_original_run(claims)
    subject = mapping['broker']['subject']
    if claims['sub'] != subject:
        raise InvalidBinding()
    binding = current_binding()
    if binding is not None:
        scope = binding['scope']
        require(scope['suite'] == 'flags-s3rch-browser'
                and mapping['tenant_id'] == scope['tenant']
                and ISSUER == scope['issuer'] and AUDIENCE in scope['clients']
                and mapping['sea_public_key'] in scope['identities']['sea'])
    member = await authorize_session_member(subject, UUID(mapping['tenant_id']))
    if member is None or claims['exp'] <= time() or configuration() != (mapping, digest):
        raise InvalidBinding()
    return {
        'schema_version': 1, 'status': 'resolved', 'permissions': [],
        'person_id': str(member.user_id), 'broker_subject': subject, 'github': {'subject': subject},
        'tenant_id': mapping['tenant_id'], 'network_id': mapping['network_id'],
        'sea_public_key': mapping['sea_public_key'], 'binding_sha256': digest, 'mapping_sha256': digest,
        'organizations': [],
    }
