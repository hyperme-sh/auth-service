from unittest.mock import AsyncMock

import httpx
import pytest
from starlette.requests import Request

from auth_service import transaction


def request(path, tenant=None):
    headers = [(b"host", b"auth-service")]
    if tenant is not None:
        headers.append((b"x-tenant-id", str(tenant).encode()))
    return Request({
        "type": "http", "scheme": "http", "method": "POST", "path": path,
        "headers": headers, "query_string": b"",
    })


@pytest.mark.parametrize("path", ["/auth/scoped-session", "/auth/network-session"])
async def test_explicit_tenant_routes_do_not_query_host_mapping(path, monkeypatch):
    monkeypatch.setattr(transaction, "is_tenancy_enabled", lambda: True)
    legacy = AsyncMock(side_effect=AssertionError("Auth owner has no tenants table"))
    resolver = AsyncMock(side_effect=AssertionError("Explicit selection does not use tenant domains"))
    monkeypatch.setattr(transaction, "get_tenant_service", legacy)
    monkeypatch.setattr(transaction, "resolve_owner_tenant", resolver)
    tenant = transaction.uuid.uuid4()
    assert await transaction.resolve_tenant(request(path), AsyncMock()) is None
    assert await transaction.resolve_tenant(request(path, tenant), AsyncMock()) == tenant
    legacy.assert_not_called()
    resolver.assert_not_awaited()


@pytest.mark.parametrize("response_status", [200, 404, 401, 503])
async def test_configured_owner_is_authoritative_for_host_lookup(response_status, monkeypatch):
    tenant = transaction.uuid.uuid4()
    real_client = httpx.AsyncClient

    def handler(req):
        assert req.url == "https://owner.example/api/v1/internal/identity/domain?host=auth-service"
        assert req.headers["authorization"] == "Bearer test-fixture"
        return httpx.Response(response_status, json={"tenant_id": str(tenant)})

    monkeypatch.setenv("USER_SERVICE_URL", "https://owner.example")
    monkeypatch.setenv("TENANT_OWNER_TOKEN", "test-fixture")
    monkeypatch.setattr(transaction, "is_tenancy_enabled", lambda: True)
    monkeypatch.setattr(transaction, "get_tenant_host", lambda _: "auth-service")
    legacy = AsyncMock(side_effect=AssertionError("Auth owner has no tenants table"))
    monkeypatch.setattr(transaction, "get_tenant_service", legacy)
    monkeypatch.setattr(transaction.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    session = AsyncMock()
    incoming = request("/auth/login")
    if response_status == 200:
        assert await transaction.resolve_tenant(incoming, session) == tenant
        assert incoming.state.frontend_host == "auth-service"
    elif response_status == 404:
        assert await transaction.resolve_tenant(incoming, session) is None
    else:
        with pytest.raises(transaction.TenantOwnerUnavailable):
            await transaction.resolve_tenant(incoming, session)
    session.rollback.assert_not_awaited()
    legacy.assert_not_called()


@pytest.mark.parametrize("path", ["/auth/scoped-session", "/auth/network-session"])
async def test_unauthenticated_scope_reaches_authentication_before_database(path, monkeypatch):
    from auth_service.app import create_app

    monkeypatch.setattr(transaction, "is_tenancy_enabled", lambda: True)
    monkeypatch.setattr(transaction.event, "listen", lambda *args: None)
    lookup = AsyncMock(side_effect=AssertionError("Unexpected tenant database lookup"))
    monkeypatch.setattr(transaction, "get_tenant_service", lookup)
    session = AsyncMock()
    app = create_app()
    app.state.session_maker = lambda: session
    session.__aenter__.return_value = session
    tenant = str(transaction.uuid.uuid4())
    body = {"tenant_id": tenant}
    if path.endswith("scoped-session"):
        body["organization_id"] = str(transaction.uuid.uuid4())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://auth-service") as client:
        response = await client.post(path, json=body)
    assert response.status_code == 401
    lookup.assert_not_called()
    session.execute.assert_not_awaited()
    session.rollback.assert_awaited_once()
    session.commit.assert_not_awaited()
