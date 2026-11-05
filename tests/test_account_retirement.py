"""Retirement checks work at async authentication boundaries without loop deadlocks."""
import asyncio
import time
import uuid
from unittest.mock import AsyncMock

import httpx
import jwt
import pytest
import respx
from controlplane_api.config import settings
from controlplane_api.exceptions import UnauthorizedException
from controlplane_identity.security.tenant_session_jwt import mint_tenant_session_jwt
from auth_service import token_validation


@pytest.fixture
def authority(monkeypatch):
    monkeypatch.setenv('ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED', 'true')
    monkeypatch.setenv('ACCOUNT_CLOSURE_GUARD_URL', 'https://closure.test')
    monkeypatch.setenv('ACCOUNT_CLOSURE_GUARD_TOKEN', 'read-only-test-secret-' + 'x' * 32)
    monkeypatch.setattr(settings, 'api_key_exchange_jwt_secret', 'session-test-secret-' + 'x' * 32)
    monkeypatch.setattr(settings, 'auth_token_validation_mode', 'jwt')


@pytest.mark.parametrize('blocked', [False, True])
@respx.mock
async def test_signed_tenant_session_checks_retirement_from_async_handler(authority, blocked):
    token = mint_tenant_session_jwt(claims={'sub': 'opaque:subject', 'email': 'a@example.test'}, tenant_id=uuid.uuid4())
    check = respx.post('https://closure.test/api/v1/internal/account-lifecycle/check').mock(return_value=httpx.Response(200, json={'blocked': blocked}))
    if blocked:
        with pytest.raises(UnauthorizedException):
            await token_validation.validate_access_token(token)
    else:
        assert (await token_validation.validate_access_token(token))['sub'] == 'opaque:subject'
    assert check.called


@pytest.mark.parametrize('reply', [{'blocked': False}, {'blocked': True}, {}, {'blocked': 'false'}])
@respx.mock
async def test_introspection_also_requires_current_retirement_authority(authority, monkeypatch, reply):
    monkeypatch.setattr(settings, 'auth_token_validation_mode', 'introspection')
    monkeypatch.setattr(token_validation, 'introspect_access_token', AsyncMock(return_value={'active': True, 'sub': 'opaque:subject', 'exp': int(time.time()) + 300}))
    check = respx.post('https://closure.test/api/v1/internal/account-lifecycle/check').mock(return_value=httpx.Response(200, json=reply))
    if reply == {'blocked': False}:
        assert (await token_validation.validate_access_token('opaque-token'))['sub'] == 'opaque:subject'
    else:
        with pytest.raises(UnauthorizedException):
            await token_validation.validate_access_token('opaque-token')
    assert check.called


async def test_auth_decoder_callback_can_progress_on_caller_event_loop(monkeypatch):
    loop = asyncio.get_running_loop()
    progressed = asyncio.Event()
    def decode(_):
        import concurrent.futures
        complete = concurrent.futures.Future()
        def callback():
            progressed.set()
            complete.set_result(None)
        loop.call_soon_threadsafe(callback)
        complete.result(timeout=2)
        return {'sub': 'checked'}
    monkeypatch.setattr(token_validation, 'try_decode_api_key_session_jwt', lambda _: None)
    monkeypatch.setattr(token_validation, 'try_decode_tenant_session_jwt', decode)
    assert (await token_validation.validate_access_token('session'))['sub'] == 'checked'
    assert progressed.is_set()
