"""Explicit owner grants for identity transfer, rechecked on every token use."""
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid

from jwt import InvalidTokenError

CAPABILITY = 'acl:identity:transfer'
CLAIM = 'identity_transfer_grant'
MEDIA = ('acl:media:read', 'acl:media:write')
PORTAL_SUBJECT = 'c92fc0dd-c922-5c71-88da-bd91b38d14a4'
PORTAL_TENANT = '8f8e8d8c-7b6a-4a59-8c3d-2e1f0a9b8c7d'
PORTAL_ISSUER = 'https://auth.test.hyperme.sh/realms/controlplane'
PORTAL_CLIENT = 'controlplane-frontend'


def require(value):
    if not value:
        raise ValueError('Transfer permission refused')


def unique(pairs):
    value = dict(pairs)
    require(len(value) == len(pairs))
    return value


def configuration():
    name = os.environ.get('AUTH_TRANSFER_GRANTS_FILE')
    if not name:
        return []
    path = Path(name)
    require(path.is_absolute() and path.resolve() == path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and info.st_mode & 0o077 == 0)
        raw = stream.read(65537)
    require(len(raw) <= 65536)
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: require(False))
    require(type(value) is dict and set(value) == {'version', 'grants'})
    require(type(value['version']) is int and value['version'] == 1)
    grants = value['grants']
    require(type(grants) is list and len(grants) <= 128)
    ids = set()
    for grant in grants:
        require(type(grant) is dict and set(grant) == {
            'id', 'issuer', 'subject', 'client', 'tenant', 'organization',
            'scopeGeneration', 'scopeManifest', 'expiresAt', 'capability'})
        for key in set(grant) - {'expiresAt'}:
            require(type(grant[key]) is str and 0 < len(grant[key]) <= 512)
        require(grant['capability'] == CAPABILITY)
        require(grant['id'] not in ids)
        ids.add(grant['id'])
        for key in ('tenant', 'organization'):
            require(str(uuid.UUID(grant[key])) == grant[key])
        require(len(grant['scopeManifest']) == 64
                and all(c in '0123456789abcdef' for c in grant['scopeManifest']))
        require(type(grant['expiresAt']) is int and grant['expiresAt'] > 0)
    return grants


def digest(grant):
    return hashlib.sha256(json.dumps(grant, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def without_transfer(claims):
    """Provider or source-tenant scopes never confer this capability."""
    result = dict(claims)
    result['scope'] = ' '.join(s for s in str(claims.get('scope') or 'openid').split()
                               if s not in (CAPABILITY, *MEDIA))
    result.pop(CLAIM, None)
    return result


def portal_media(grant):
    # The existing signed transfer grant is the deployment opt-in. Keep its
    # wire format and digest compatible with independently updated consumers.
    return (grant['subject'], grant['tenant'], grant['issuer'], grant['client']) == (
        PORTAL_SUBJECT, PORTAL_TENANT, PORTAL_ISSUER, PORTAL_CLIENT)



def select(claims, grant, *, check_media_run=True):
    matches = [item for item in configuration()
               if item['issuer'] == claims.get('iss')
               and item['subject'] == claims.get('sub')
               and item['client'] == (claims.get('azp') or claims.get('client_id'))
               and item['tenant'] == str(grant.tenant_id)
               and item['organization'] == str(grant.organization_id)
               and item['scopeGeneration'] == grant.generation
               and item['scopeManifest'] == grant.manifest_sha256
               and item['expiresAt'] > int(time.time())]
    require(len(matches) == 1)
    selected = matches[0]
    if check_media_run and portal_media(selected):
        from controlplane_identity.nightly import current_binding, require_original_run
        binding = current_binding()
        require(binding is not None)
        scope = binding['scope']
        require(scope['suite'] == 'portal-device-transfer' and scope['realm'] == 'controlplane'
                and scope['issuer'] == selected['issuer'] and scope['subject'] == selected['subject']
                and scope['tenant'] == selected['tenant'] and scope['organization'] == selected['organization']
                and selected['client'] in scope['clients'] and 'https://portal.test.hyperme.sh' in scope['origins'])
        try:
            require_original_run(claims)
        except InvalidTokenError as exc:
            raise ValueError("Portal media run refused") from exc
    return selected


def attach(payload, grant):
    payload['scope'] = ' '.join([*without_transfer(payload)['scope'].split(), CAPABILITY])
    if portal_media(grant):
        payload['scope'] += ' ' + ' '.join(MEDIA)
    payload[CLAIM] = {'id': grant['id'], 'sha256': digest(grant), 'issuer': grant['issuer']}
    payload['exp'] = min(payload['exp'], grant['expiresAt'])


async def validate(claims):
    scopes = set(str(claims.get('scope') or '').split())
    media = scopes.intersection(MEDIA)
    if CAPABILITY not in scopes:
        if media and claims.get('spanopticon_auth') != 'api_key':
            return without_transfer(claims)
        return claims
    # A provider scope is not an Auth capability grant; preserve ordinary login.
    if claims.get('spanopticon_auth') != 'tenant_session':
        return without_transfer(claims)
    require(claims.get('iss') == 'https://spanopticon.internal/tenant-session')
    require(claims.get('scope_version') == 1 and claims.get('scope_kind') == 'organization')
    marker = claims.get(CLAIM)
    require(type(marker) is dict and set(marker) == {'id', 'sha256', 'issuer'})
    from auth_service.scoped_session import current_scope
    grant = await current_scope(claims.get('sub'), uuid.UUID(claims['tenant_id']),
                                uuid.UUID(claims['organization_id']))
    require(grant is not None and grant.network_id == claims.get('network_id')
            and grant.generation == claims.get('scope_generation')
            and grant.manifest_sha256 == claims.get('scope_manifest_sha256'))
    selected = select({'iss': marker['issuer'], 'sub': claims.get('sub'),
                       'azp': claims.get('azp'), 'nightly_run': claims.get('nightly_run')}, grant, check_media_run=bool(media))
    if media:
        require(portal_media(selected) and media == set(MEDIA))
    require(marker['id'] == selected['id'] and marker['sha256'] == digest(selected))
    require(type(claims.get('exp')) is int and claims['exp'] <= selected['expiresAt'])
    return claims
