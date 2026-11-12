"""Private startup deployment mapping and verified broker-account selection.

No authentication, key creation, grants, or database writes happen here.
The binding format preserves Infra's canonical version 1 configuration.
"""
import base64
import hashlib
import json
import os
import re
import stat
from urllib.parse import urlsplit
from uuid import UUID

MAX_BYTES = 16384
ORGANIZATIONS = frozenset(('fyberlabs', 'tennesseewindage', 'hyperme.sh'))

class InvalidBinding(ValueError):
    def __init__(self):
        super().__init__('Startup identity configuration refused')


def fields(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise InvalidBinding()


def identifier(value):
    if type(value) is not str:
        raise InvalidBinding()
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise InvalidBinding() from None
    if not parsed.int or str(parsed) != value:
        raise InvalidBinding()


def label(value):
    if type(value) is not str or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', value):
        raise InvalidBinding()


def sea_key(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}', value):
        raise InvalidBinding()
    coordinates = []
    for part in value.split('.'):
        raw = base64.urlsafe_b64decode(part + '=')
        if base64.urlsafe_b64encode(raw).decode().rstrip('=') != part:
            raise InvalidBinding()
        coordinates.append(int.from_bytes(raw, 'big'))
    x, y = coordinates
    prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    if x >= prime or y >= prime or (y*y - (x*x*x - 3*x + b)) % prime:
        raise InvalidBinding()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidBinding()
        result[key] = value
    return result


def canonical_binding(raw):
    """Return a private canonical snapshot; callers must not print this value."""
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BYTES:
            raise InvalidBinding()
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
        fields(doc, ('version', 'entra', 'sea_public_key', 'organizations', 'platform_admin', 'keycloak_admin'))
        if type(doc['version']) is not int or doc['version'] != 1:
            raise InvalidBinding()
        sea_key(doc['sea_public_key'])
        entra = doc['entra']
        fields(entra, ('tenant_id', 'object_id', 'issuer', 'audience', 'subject', 'broker'))
        for name in ('tenant_id', 'object_id', 'audience'):
            identifier(entra[name])
        if entra['issuer'] != 'https://login.microsoftonline.com/' + entra['tenant_id'] + '/v2.0':
            raise InvalidBinding()
        if type(entra['subject']) is not str or not re.fullmatch(r'[\x21-\x7e]{1,256}', entra['subject']):
            raise InvalidBinding()
        label(entra['broker'])
        organizations = doc['organizations']
        fields(organizations, ORGANIZATIONS)
        ids = set()
        for organization in organizations.values():
            fields(organization, ('tenant_id', 'organization_id', 'roles'))
            identifier(organization['tenant_id'])
            identifier(organization['organization_id'])
            if organization['organization_id'] in ids:
                raise InvalidBinding()
            ids.add(organization['organization_id'])
            roles = organization['roles']
            if type(roles) is not list or not roles or any(type(role) is not str for role in roles):
                raise InvalidBinding()
            if len(roles) != len(set(roles)) or not set(roles) <= {'owner', 'admin'}:
                raise InvalidBinding()
            organization['roles'] = sorted(roles)
        fields(doc['platform_admin'], ('spanopticon', 'hyperme.sh'))
        if any(type(value) is not bool for value in doc['platform_admin'].values()):
            raise InvalidBinding()
        fields(doc['keycloak_admin'], ('realm', 'enabled'))
        label(doc['keycloak_admin']['realm'])
        if type(doc['keycloak_admin']['enabled']) is not bool:
            raise InvalidBinding()
        return (json.dumps(doc, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, OverflowError):
        raise InvalidBinding() from None


def read_private(path):
    """Read only a private regular file owned by the executing deployment identity."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise InvalidBinding()
        with os.fdopen(descriptor, 'rb') as handle:
            descriptor = None
            return handle.read(MAX_BYTES + 1)
    except (OSError, ValueError):
        raise InvalidBinding() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)





def _encode(value):
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if len(raw) > MAX_BYTES:
            raise InvalidBinding()
        return raw
    except (ValueError, TypeError, RecursionError, UnicodeError, OverflowError):
        raise InvalidBinding() from None


def binding_fingerprint(binding):
    return hashlib.sha256(canonical_binding(_encode(binding))).hexdigest()


def validate(value):
    """Return a detached mapping with separate raw Entra and broker settings."""
    try:
        # JSON round-trip snapshots caller input and bounds nested or unusual values.
        doc = json.loads(_encode(value), object_pairs_hook=unique_object)
        fields(doc, ('schema_version', 'binding', 'binding_sha256', 'owner'))
        if type(doc['schema_version']) is not int or doc['schema_version'] != 1:
            raise InvalidBinding()
        binding = json.loads(canonical_binding(_encode(doc['binding'])))
        if type(doc['binding_sha256']) is not str or doc['binding_sha256'] != binding_fingerprint(binding):
            raise InvalidBinding()
        owner = doc['owner']
        fields(owner, ('tenant_id', 'network_id', 'profile', 'broker'))
        identifier(owner['tenant_id'])
        if type(owner['network_id']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}', owner['network_id']):
            raise InvalidBinding()
        fields(owner['profile'], ('email',))
        email = owner['profile']['email']
        if type(email) is not str or len(email) > 254 or not re.fullmatch(r'[^\s@\x00-\x1f\x7f]{1,64}@[^\s@\x00-\x1f\x7f]{1,253}', email):
            raise InvalidBinding()
        fields(owner['broker'], ('issuer', 'audience'))
        issuer, audience = owner['broker']['issuer'], owner['broker']['audience']
        if type(issuer) is not str or len(issuer) > 2048 or re.search(r'[\s\x00-\x1f\x7f\\]', issuer):
            raise InvalidBinding()
        parsed = urlsplit(issuer)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise InvalidBinding()
        _ = parsed.port
        if type(audience) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}', audience):
            raise InvalidBinding()
        doc['binding'] = binding
        return doc
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, OverflowError):
        raise InvalidBinding() from None


def fingerprint(value):
    return hashlib.sha256(_encode(validate(value))).hexdigest()


def load(path):
    """Load only a bounded, owner-private, single-link regular file."""
    try:
        raw = read_private(path)
        if not 1 <= len(raw) <= MAX_BYTES:
            raise InvalidBinding()
        return validate(json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise InvalidBinding() from None


def verify_claims(config, claims, *, expected_subject=None):
    """Select an account from already authenticated Keycloak broker claims.

    Caller verifies signature, time, issuer, audience and authorized client first.
    This does not accept raw Entra tokens or use email/roles to select a person.
    The initial subject may be unbound; later requests must supply the stored one.
    """
    mapping = validate(config)
    entra, broker = mapping['binding']['entra'], mapping['owner']['broker']
    if type(claims) is not dict:
        raise InvalidBinding()
    audiences = claims.get('aud')
    if type(audiences) is str:
        audiences = [audiences]
    if (type(audiences) is not list or not 1 <= len(audiences) <= 32 or
            any(type(item) is not str for item in audiences) or
            len(set(audiences)) != len(audiences) or broker['audience'] not in audiences):
        raise InvalidBinding()
    expected = {'iss': broker['issuer'], 'login_provider': entra['broker'],
                'entra_tenant_id': entra['tenant_id'], 'entra_object_id': entra['object_id']}
    if any(type(claims.get(key)) is not str or claims[key] != value for key, value in expected.items()):
        raise InvalidBinding()
    if claims.get('azp') not in (None, broker['audience']) or 'spanopticon_auth' in claims or 'purpose' in claims:
        raise InvalidBinding()
    subject = claims.get('sub')
    if type(subject) is not str or not re.fullmatch(r'[\x21-\x7e]{1,255}', subject):
        raise InvalidBinding()
    if expected_subject is not None and (type(expected_subject) is not str or subject != expected_subject):
        raise InvalidBinding()
    return subject
