"""Probe contracts without peer services or a live database."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, Mock

import httpx
from sqlalchemy.exc import SQLAlchemyError

from auth_service import transaction
from auth_service.app import create_app
from auth_service.health import LIVENESS_PATH, READINESS_PATH


async def test_local_probes_do_not_resolve_a_tenant_or_use_a_request_session(monkeypatch):
    app = create_app(enable_db_middleware=False)
    app.add_middleware(transaction.AuthTransactionMiddleware)
    app.state.session_maker = Mock(side_effect=AssertionError("Unexpected request session"))
    resolve = AsyncMock(side_effect=AssertionError("Unexpected tenant lookup"))
    monkeypatch.setattr(transaction, "resolve_tenant", resolve)
    execute = AsyncMock()

    @asynccontextmanager
    async def connect():
        yield Mock(execute=execute)

    app.state.async_engine = Mock(connect=connect)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="https://auth.example.invalid") as client:
        assert (await client.get(LIVENESS_PATH)).status_code == 200
        execute.assert_not_awaited()
        assert (await client.get(READINESS_PATH)).status_code == 200
        assert str(execute.await_args.args[0]) == "SELECT 1"
        execute.side_effect = SQLAlchemyError("Database unavailable")
        assert (await client.get(READINESS_PATH)).status_code == 503
        assert (await client.get(LIVENESS_PATH)).status_code == 200
        app.state.async_engine = None
        assert (await client.get(READINESS_PATH)).status_code == 503
    resolve.assert_not_awaited()
    app.state.session_maker.assert_not_called()
