"""Contract transport substitutes only; no provider or database operations."""
from dataclasses import replace
from uuid import UUID

import httpx
import pytest

from auth_service.canary import Binding, Unavailable, probe

BINDING = Binding('declared-person', UUID(int=1), UUID(int=2), UUID(int=3), True)
FACTS = dict(subject=BINDING.subject, tenant_id=str(BINDING.tenant),
             member_id=str(BINDING.member), session_ref='a' * 64, second_factor_at=None)


def reply(body, status=200, **headers):
    return httpx.Response(status, json=body, headers={'cache-control': 'no-store', **headers})


async def invoke(handler, **kwargs):
    return await probe(kwargs.pop('binding', BINDING), url=kwargs.pop('url', 'https://auth.example.invalid'),
                       tenant_token='private-tenant', original_token='private-browser',
                       transport=httpx.MockTransport(handler), **kwargs)


async def test_retained_session_and_wrong_tenant():
    calls = []
    def handler(request):
        calls.append(request)
        assert request.headers['authorization'] == 'Bearer private-tenant'
        assert request.headers['x-auth-session-token'] == 'private-browser'
        if request.headers['x-tenant-id'] == str(BINDING.other_tenant):
            return reply({'detail': 'Verified browser session required'}, 403)
        return reply(FACTS | {'source': 'auth_connect_session_v2'})
    assert await invoke(handler, previous=FACTS) == FACTS
    assert len(calls) == 2


@pytest.mark.parametrize('enabled', [False, 1, 'true'])
async def test_disabled_before_io(enabled):
    def handler(_):
        pytest.fail('Disabled canary performed I/O')
    with pytest.raises(Unavailable):
        await invoke(handler, binding=replace(BINDING, enabled=enabled))


@pytest.mark.parametrize('previous', [{}, FACTS | {'subject': 'other'}, FACTS | {'second_factor_at': True},
                                      FACTS | {'session_ref': 'bad'}, FACTS | {'member_id': str(UUID(int=7))}])
async def test_invalid_saved_session_before_io(previous):
    def handler(_):
        pytest.fail('Invalid original session performed I/O')
    with pytest.raises(Unavailable):
        await invoke(handler, previous=previous)


@pytest.mark.parametrize('expected,status,body', [
    ('revoked', 403, {'detail': 'Verified active tenant member required', 'code': 'membership_revoked'}),
    ('ended', 403, {'detail': 'Verified browser session required', 'code': 'issuer_token_inactive'}),
    ('unavailable', 503, {'detail': 'Session verification unavailable'}),
])
async def test_exact_refusals(expected, status, body):
    assert await invoke(lambda _: reply(body, status), previous=FACTS, expected=expected) == FACTS
    for wrong in {'revoked', 'ended', 'unavailable'} - {expected}:
        with pytest.raises(Unavailable):
            await invoke(lambda _: reply(body, status), previous=FACTS, expected=wrong)


@pytest.mark.parametrize('field,value', [('subject', 'other'), ('tenant_id', str(UUID(int=2))),
                                         ('member_id', str(UUID(int=4))), ('session_ref', 'b' * 64),
                                         ('second_factor_at', '2020-01-01T00:00:00+00:00')])
async def test_no_identity_or_factor_changes(field, value):
    with pytest.raises(Unavailable):
        await invoke(lambda _: reply(FACTS | {'source': 'auth_connect_session_v2', field: value}), previous=FACTS)


@pytest.mark.parametrize('response', [reply([], 200), reply({}, 302), reply({}, 503),
    reply(FACTS | {'source': 'auth_connect_session_v2'}, **{'cache-control': 'public'}),
    httpx.Response(200, content=b'x' * 65537, headers={'cache-control': 'no-store'})])
async def test_invalid_or_unbounded_response(response):
    with pytest.raises(Unavailable):
        await invoke(lambda _: response)


async def test_wrong_tenant_acceptance_fails():
    with pytest.raises(Unavailable):
        await invoke(lambda _: reply(FACTS | {'source': 'auth_connect_session_v2'}))


@pytest.mark.parametrize('url', ['http://auth.example.invalid', 'https://user:pass@example.invalid',
                                 'https://example.invalid/path', 'https://example.invalid/?q=1'])
async def test_unsafe_endpoint_before_io(url):
    def handler(_):
        pytest.fail('Unsafe endpoint used')
    with pytest.raises(ValueError):
        await invoke(handler, url=url)


async def test_expired_credential_does_not_prove_issuer_logout():
    with pytest.raises(Unavailable):
        await invoke(lambda _: reply({'detail': 'Verified browser session required'}, 403),
                     previous=FACTS, expected='ended')
