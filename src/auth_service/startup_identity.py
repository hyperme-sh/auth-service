"""Startup binding uses User commands; verified login never creates a person."""
import os
import uuid
from urllib.parse import urlsplit
from pathlib import Path
import httpx
from ._startup_contract import load, fingerprint, verify_claims


def configuration():
    if os.environ.get('STARTUP_IDENTITY_ENABLED') != '1':
        raise ValueError('Startup identity is not enabled')
    return load(Path(os.environ.get('STARTUP_IDENTITY_CONFIG_FILE','')))


async def owner(operation, config, **payload):
    url = os.environ.get('AUTH_IDENTITY_OWNER_URL','').rstrip('/')
    token_name = 'AUTH_IDENTITY_OWNER_TOKEN' if operation == 'bind' else 'USER_STARTUP_READ_TOKEN'
    token = os.environ.get(token_name,'')
    if not url or not token: raise ValueError('Startup owner configuration unavailable')
    parsed = urlsplit(url)
    local = config['environment'] == 'isolated' and parsed.hostname in ('localhost','127.0.0.1','::1')
    if (parsed.scheme != 'https' and not (local and parsed.scheme == 'http') or
        not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError('Verified startup owner endpoint required')
    async with httpx.AsyncClient(timeout=10,follow_redirects=False) as client:
        response = await client.post(url+'/api/v1/internal/startup/'+operation,
            json={'mapping_sha256':fingerprint(config), **payload}, headers={'Authorization':'Bearer '+token})
        response.raise_for_status()
        return response.json()


def checked_person(config, person):
    if (not isinstance(person,dict) or person.get('schema_version') != 1 or
        person.get('mapping_sha256') != fingerprint(config) or person.get('status') != 'reconciled' or
        person.get('tenant_id') != config['tenant_id'] or person.get('network_id') != config['network_id']):
        raise ValueError('User mapping conflicts with startup configuration')
    try:
        if str(uuid.UUID(person['person_id'])) != person['person_id']: raise ValueError()
        organizations = person['organizations']
        if [o['slug'] for o in organizations] != config['organizations']: raise ValueError()
        if len({str(uuid.UUID(o['id'])) for o in organizations}) != 3: raise ValueError()
        if any(o['roles'] != ['owner','admin'] for o in organizations): raise ValueError()
        subject = person.get('broker_subject')
        if subject is not None and (not isinstance(subject,str) or not subject.strip() or len(subject)>255): raise ValueError()
    except (ValueError,KeyError,TypeError):
        raise ValueError('User identity or organization mapping conflicts') from None
    return person


async def reconcile(config):
    person = checked_person(config, await owner('status',config))
    subject = person.get('broker_subject') or person['person_id']
    bound = await owner('bind',config,subject=subject)
    if (bound.get('mapping_sha256') != fingerprint(config) or bound.get('person_id') != person['person_id'] or
        bound.get('broker_subject') != subject or bound.get('status') != 'bound'):
        raise ValueError('Bound person differs from the selected mapping')
    return {**person, 'broker_subject':subject, 'status':'bound', 'permissions':[]}


async def resolve(config, claims):
    # This function accepts claims only from the existing signature-verifying
    # dependency. Check the immutable tuple before contacting the owner.
    verify_claims(config,claims)
    person = checked_person(config,await owner('status',config))
    if not person.get('broker_subject'): raise ValueError('Startup broker binding is incomplete')
    verify_claims(config,claims,expected_subject=person['broker_subject'])
    return {**person, 'status':'resolved', 'permissions':[]}
