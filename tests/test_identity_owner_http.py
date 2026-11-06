"""Auth sends authenticated commands and fails closed on owner failures."""
from types import SimpleNamespace
import httpx
import pytest
from auth_service import identity_owner
from auth_service.enrollment import EnrollmentError

@pytest.mark.asyncio
async def test_missing_owner_configuration_never_sends(monkeypatch):
    monkeypatch.delenv('AUTH_IDENTITY_OWNER_URL', raising=False)
    with pytest.raises(RuntimeError, match='configuration'):
        await identity_owner.call('get-wallet', subject='verified-subject')

@pytest.mark.asyncio
@pytest.mark.parametrize('status', [200, 401, 409, 500])
async def test_owner_command_authentication_and_failure_mapping(monkeypatch, status):
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_URL', 'https://owner.example.test')
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_TOKEN', 'fixture-owner-token')
    def receive(request):
        assert request.headers['Authorization'] == 'Bearer fixture-owner-token'
        assert request.url.path == '/api/v1/internal/identity/enroll'
        return httpx.Response(status, json={'detail':'identity conflict'} if status!=200 else {'granted':[]})
    factory=httpx.AsyncClient
    monkeypatch.setattr(identity_owner,'httpx',SimpleNamespace(AsyncClient=lambda **kw:factory(transport=httpx.MockTransport(receive),**kw)))
    if status==200:
        assert await identity_owner.call('enroll', user={'sub':'verified-subject'}) == {'granted':[]}
    else:
        with pytest.raises(EnrollmentError if status==409 else httpx.HTTPStatusError):
            await identity_owner.call('enroll', user={'sub':'verified-subject'})
