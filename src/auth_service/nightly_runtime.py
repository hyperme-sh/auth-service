"""Explicit TEST-only configuration and independently committed owner operations."""
import hashlib
import hmac
import json
import os
from pathlib import Path
from contextvars import ContextVar
from auth_service import nightly_state as state

admission = ContextVar('nightly_admission', default=None)


def configuration():
    path = os.environ.get('AUTH_NIGHTLY_RUN_CONFIG_FILE')
    if path is None: return None
    try:
        with Path(path).open('rb') as stream: raw = stream.read(65537)
        state.require(len(raw) <= 65536)
        value = json.loads(raw)
        state.fields(value, 'version ownerKeys scopes')
        state.require(type(value['version']) is int and value['version'] == 1)
        state.require(type(value['ownerKeys']) is dict and state.BASE_OWNERS <= set(value['ownerKeys']) <= state.OWNERS)
        state.require(all(isinstance(k, str) and state.HEX.fullmatch(k) for k in value['ownerKeys'].values()))
        state.require(len(set(value['ownerKeys'].values())) == len(value['ownerKeys']))
        state.require(type(value['scopes']) is dict and 0 < len(value['scopes']) <= 5)
        for suite, scope in value['scopes'].items():
            state.scope(scope); state.require(scope['suite'] == suite)
        return value
    except Exception: raise state.Refused() from None


def authenticate(config, raw, signature):
    state.require(config is not None and len(raw) <= 16384 and isinstance(signature, str) and state.HEX.fullmatch(signature))
    value = json.loads(raw); state.command(value)
    key = bytes.fromhex(config['ownerKeys'][value['owner']])
    state.require(hmac.compare_digest(hmac.new(key, raw, hashlib.sha256).hexdigest(), signature))
    if value['action'] == 'register':
        state.require(config['scopes'].get(value['scope']['suite']) == value['scope'])
    return value


async def verify_claims(claims):
    """Called only after cryptographic token validation; never decode-only identity."""
    from controlplane_identity.nightly import current_binding, require_original_run
    if current_binding() is not None:
        require_original_run(claims)
        return claims
    config = configuration()
    if config is None:
        state.require('nightly_run' not in claims)
        return claims
    managed = any(scope['subject'] == claims.get('sub') for scope in config['scopes'].values())
    binding = admission.get()
    if binding is None and not managed and 'nightly_run' not in claims: return claims
    state.require(binding is not None and not binding.get('_closed', False))
    state.fields(claims.get('nightly_run'), 'run generation')
    state.require(claims['nightly_run'] == {k: binding[k] for k in ('run', 'generation')}
                  and claims.get('sub') == binding['scope']['subject'])
    return claims
