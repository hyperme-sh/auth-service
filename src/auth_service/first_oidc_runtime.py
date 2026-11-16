"""Owner-only first-link configuration, absent by default."""
import hmac
import json
import os
import re
from pathlib import Path
import stat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from auth_service import first_oidc_link as core


def unique(pairs):
    value=dict(pairs);core.require(len(value)==len(pairs));return value


def configuration():
    name=os.environ.get('AUTH_FIRST_OIDC_LINK_CONFIG_FILE')
    if name is None:return None
    path=Path(name);core.require(path.is_absolute() and path.resolve()==path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        core.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1 and info.st_mode&0o077==0)
        raw=stream.read(262145)
    core.require(len(raw)<=262144)
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:core.require(False))
    core.exact(value,'version serviceToken bindings providerJwks signer signingKeyPem')
    core.require(type(value['version']) is int and value['version']==1)
    core.require(type(value['serviceToken']) is str and re.fullmatch(r'[A-Za-z0-9_-]{43,128}',value['serviceToken']))
    core.require(type(value['bindings']) is list and 1<=len(value['bindings'])<=128)
    identities=set()
    for b in value['bindings']:
        core.exact(b,'principal issuer tenant subject clientId tenantClaim sequence expiresAt')
        identity=core.fingerprint({k:b[k] for k in ('issuer','tenant','subject')})
        core.require(identity not in identities);identities.add(identity)
    core.require(type(value['signingKeyPem']) is str and len(value['signingKeyPem'])<=8192)
    load_pem_private_key(value['signingKeyPem'].encode(),password=None)
    return value


def authenticate(config, authorization):
    core.require(config is not None and type(authorization) is str)
    core.require(hmac.compare_digest(authorization.encode(),('Bearer '+config['serviceToken']).encode()))


def select(config, record):
    core.require(type(record) is dict and type(record.get('cred')) is dict)
    matches=[b for b in config['bindings'] if b['principal']==record.get('principal') and
        record['cred']==dict(iss=b['issuer'],tenant=b['tenant'],sub=b['subject'])]
    core.require(len(matches)==1)
    return matches[0]
