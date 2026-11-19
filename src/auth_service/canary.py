"""Bounded, inactive-by-default checks of retained Auth browser sessions."""
from dataclasses import dataclass
from datetime import datetime, timezone
import asyncio
import json
import re
from urllib.parse import urlsplit
from uuid import UUID

import httpx


class Unavailable(ValueError):
    """A declared session or refusal could not be established."""


@dataclass(frozen=True)
class Binding:
    subject: str
    tenant: UUID
    other_tenant: UUID
    member: UUID
    enabled: bool = False

    def __post_init__(self):
        if not isinstance(self.subject, str) or not self.subject.strip() or len(self.subject) > 512:
            raise ValueError('Declared subject required')
        if any(type(v) is not UUID or not v.int for v in (self.tenant, self.other_tenant, self.member)) or self.tenant == self.other_tenant:
            raise ValueError('Distinct declared tenant scopes required')


def endpoint(value):
    parsed = urlsplit(value)
    if (parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ('', '/')
            or (parsed.scheme == 'http' and parsed.hostname not in ('127.0.0.1', '::1'))):
        raise ValueError('HTTPS or isolated loopback Auth endpoint required')
    return value.rstrip('/')


def credential(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 32768 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError('Private session credential required')
    return value


def continuity(binding, value):
    """Validate retained public facts before any network operation."""
    expected = {'subject', 'tenant_id', 'member_id', 'session_ref', 'second_factor_at'}
    if (not isinstance(value, dict) or set(value) != expected
            or value['subject'] != binding.subject or value['tenant_id'] != str(binding.tenant)
            or value['member_id'] != str(binding.member)
            or not isinstance(value['session_ref'], str) or not re.fullmatch('[0-9a-f]{64}', value['session_ref'])):
        raise Unavailable('Original session identity differs')
    factor = value['second_factor_at']
    if factor is not None:
        try:
            stamp = datetime.fromisoformat(factor)
            if stamp.utcoffset() is None or stamp > datetime.now(timezone.utc):
                raise ValueError()
        except (TypeError, ValueError):
            raise Unavailable('Invalid original second factor') from None
    return dict(value)


async def probe(binding, *, url, tenant_token, original_token, previous=None,
                expected='active', transport=None):
    """Observe the same session across changes; never mint or end a session.

    The authorized runner performs browser login, refresh and issuer logout.
    It retains both original credentials privately across revision changes.
    User membership is rechecked by Auth. Expected refusal is explicit; an
    outage never satisfies a revocation or logout assertion.
    """
    if binding.enabled is not True:
        raise Unavailable('Auth canary binding disabled')
    if expected not in ('active', 'revoked', 'ended', 'unavailable'):
        raise ValueError('Unknown session expectation')
    if previous is not None:
        previous = continuity(binding, previous)
    if expected != 'active' and previous is None:
        raise Unavailable('Original active session required before refusal')
    url = endpoint(url)
    headers = {'Authorization': 'Bearer ' + credential(tenant_token),
               'X-Auth-Session-Token': credential(original_token),
               'X-Tenant-ID': str(binding.tenant), 'Accept-Encoding': 'identity'}
    async with asyncio.timeout(20):
        async with httpx.AsyncClient(timeout=5, trust_env=False, follow_redirects=False, transport=transport) as client:
            async def request(scope):
                async with client.stream('GET', url + '/auth/connect-session-context',
                                         headers=headers | {'X-Tenant-ID': str(scope)}) as response:
                    if response.headers.get('cache-control') != 'no-store' or response.headers.get('content-encoding', 'identity') != 'identity':
                        raise Unavailable('Unsafe Auth response')
                    raw = bytearray()
                    async for part in response.aiter_bytes():
                        raw.extend(part)
                        if len(raw) > 65536:
                            raise Unavailable('Auth response oversized')
                    try:
                        body = json.loads(raw)
                    except (ValueError, RecursionError):
                        raise Unavailable('Invalid Auth response') from None
                    if not isinstance(body, dict):
                        raise Unavailable('Invalid Auth response shape')
                    return response.status_code, body
            status, facts = await request(binding.tenant)
            if expected != 'active':
                code, detail = {
                    'revoked': (403, 'Verified active tenant member required'),
                    'ended': (403, 'Verified browser session required'),
                    'unavailable': (503, 'Session verification unavailable'),
                }[expected]
                required = {'detail': detail}
                if expected == 'revoked':
                    required['code'] = 'membership_revoked'
                elif expected == 'ended':
                    required['code'] = 'issuer_token_inactive'
                if status != code or facts != required:
                    raise Unavailable('Expected Auth refusal absent')
                return previous
            if status != 200 or facts.get('source') != 'auth_connect_session_v2':
                raise Unavailable('Active Auth session unavailable')
            current = continuity(binding, {k: facts.get(k) for k in
                                 ('subject', 'tenant_id', 'member_id', 'session_ref', 'second_factor_at')})
            if previous is not None and current != previous:
                raise Unavailable('Original Auth session changed')
            status, facts = await request(binding.other_tenant)
            if status != 403 or facts != {'detail': 'Verified browser session required'}:
                raise Unavailable('Wrong tenant scope was not refused')
            return current
