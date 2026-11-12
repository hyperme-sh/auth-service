"""Startup binding contract shared by owner services; no storage or privilege writes."""
import base64
import hashlib
import json
import re
from urllib.parse import urlsplit
import uuid

ORGANIZATIONS = ('fyberlabs', 'tennesseewindage', 'hyperme.sh')
FIELDS = {'schema_version', 'environment', 'entra_tenant_id', 'entra_account_id', 'sea_public_key',
          'tenant_id', 'network_id', 'email', 'issuer', 'audience', 'organizations'}


def refuse(field):
    raise ValueError('Invalid startup binding: ' + field)


def identifier(value, field):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        refuse(field)
    if str(parsed) != value or parsed.int == 0:
        refuse(field)
    return value


def sea_key(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}', value):
        refuse('sea_public_key')
    coordinates = []
    for part in value.split('.'):
        raw = base64.urlsafe_b64decode(part + '=')
        if base64.urlsafe_b64encode(raw).decode().rstrip('=') != part:
            refuse('sea_public_key')
        coordinates.append(int.from_bytes(raw, 'big'))
    # Gun SEA public keys encode the P-256 affine x and y coordinates.
    prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    x, y = coordinates
    if x >= prime or y >= prime or (y*y - (x*x*x - 3*x + b)) % prime:
        refuse('sea_public_key')
    return value


def validate(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        refuse('fields')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        refuse('schema_version')
    if value['environment'] not in ('isolated', 'test', 'production'):
        refuse('environment')
    for field in ('entra_tenant_id', 'entra_account_id', 'tenant_id'):
        identifier(value[field], field)
    sea_key(value['sea_public_key'])
    for field in ('network_id', 'audience'):
        if not isinstance(value[field], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}', value[field]):
            refuse(field)
    if not isinstance(value['email'], str) or not re.fullmatch(r'[^\s@]{1,64}@[^\s@]{1,253}', value['email']):
        refuse('email')
    if not isinstance(value['issuer'], str): refuse('issuer')
    if any(c.isspace() or ord(c) < 32 for c in value['issuer']): refuse('issuer')
    try:
        issuer = urlsplit(value['issuer'])
        _ = issuer.port
    except ValueError:
        refuse('issuer')
    if issuer.scheme != 'https' or not issuer.hostname or issuer.username or issuer.password or issuer.query or issuer.fragment:
        refuse('issuer')
    if value['organizations'] != list(ORGANIZATIONS):
        refuse('organizations')
    return dict(value)


def fingerprint(value):
    return hashlib.sha256(json.dumps(validate(value), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: refuse('duplicate_field')
            result[key] = value
        return result
    try:
        raw = path.read_bytes()
        if len(raw) > 16384: refuse('document_size')
        value = json.loads(raw, object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError):
        refuse('configuration_file')
    return validate(value)



def verify_claims(config, claims, *, expected_subject=None):
    """Check already signature-verified broker claims; never accept raw JWT input.

    Authentication must use the existing OIDC validator before calling here.
    Matching email, application roles and user-supplied attributes are irrelevant.
    """
    validate(config)
    if not isinstance(claims, dict): refuse('verified_claims')
    audiences = claims.get('aud')
    audiences = audiences if isinstance(audiences, list) else [audiences]
    if claims.get('iss') != config['issuer']: refuse('issuer')
    if config['audience'] not in audiences: refuse('audience')
    if claims.get('azp') not in (None, config['audience']): refuse('authorized_party')
    if claims.get('login_provider') != 'microsoft': refuse('provider')
    if claims.get('entra_tenant_id') != config['entra_tenant_id']: refuse('entra_tenant_id')
    if claims.get('entra_object_id') != config['entra_account_id']: refuse('entra_account_id')
    subject = claims.get('sub')
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 255:
        refuse('subject')
    if expected_subject is not None and subject != expected_subject: refuse('subject')
    if claims.get('spanopticon_auth') or claims.get('purpose'): refuse('ordinary_oidc')
    return subject
