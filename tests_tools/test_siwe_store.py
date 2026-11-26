"""Store selection and failure contracts without a database or Redis server."""
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from sqlalchemy.exc import OperationalError
from auth_service.siwe import SiweError
from auth_service.siwe_nonces import nonce_runtime, SiweStoreUnavailable
from auth_service.siwe_postgres import PostgresChallengeStore


class Engine:
    def __init__(self, row=None, fail=False):
        self.row = row; self.fail = fail; self.committed = False
        self.dispose = AsyncMock()
        self.calls = []
    @asynccontextmanager
    async def begin(self):
        yield self
        self.committed = True
    @asynccontextmanager
    async def connect(self):
        yield self
    async def scalar(self, *args, **kwargs):
        return 0
    async def execute(self, statement, params=None):
        if self.fail: raise OperationalError('private statement', {}, RuntimeError('private password'))
        self.calls.append((str(statement), params))
        return SimpleNamespace(mappings=lambda: SimpleNamespace(one_or_none=lambda: self.row))


@pytest.mark.asyncio
@pytest.mark.parametrize('row,error', [(None, SiweError), ({'usable':False,'challenge':{}}, SiweError), ({'usable':True,'challenge':[]}, SiweStoreUnavailable)])
async def test_invalid_consumption_stays_committed(row, error):
    engine = Engine(row)
    with pytest.raises(error): await PostgresChallengeStore(engine).consume('person')
    assert engine.committed


@pytest.mark.asyncio
async def test_valid_consume_commits_before_returning():
    engine = Engine({'usable': True, 'challenge': {'nonce': 'value'}})
    assert await PostgresChallengeStore(engine).consume('person') == {'nonce': 'value'}
    assert engine.committed
    assert 'DELETE' in engine.calls[0][0] and 'RETURNING' in engine.calls[0][0]


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['put', 'consume', 'expire'])
async def test_database_failures_are_redacted_and_do_not_fallback(operation):
    store = PostgresChallengeStore(Engine(fail=True))
    with pytest.raises(SiweStoreUnavailable, match='^SIWE nonce storage unavailable$'):
        await getattr(store, operation)('person', *([{'nonce':'value'}] if operation == 'put' else []))


@pytest.mark.asyncio
async def test_postgres_selection_closes_engine_and_ignores_redis(monkeypatch):
    from auth_service import database
    engine = Engine()
    monkeypatch.setenv('AUTH_SIWE_STORE', 'postgres')
    monkeypatch.setenv('AUTH_SIWE_DATABASE_URL', 'postgresql://user:secret@db/owner')
    monkeypatch.setenv('REDIS_URL', 'redis://must-not-be-used/0')
    monkeypatch.setattr(database, 'create_async_engine', lambda *args, **kwargs: engine)
    with pytest.raises(RuntimeError):
        async with nonce_runtime() as store:
            assert isinstance(store, PostgresChallengeStore)
            raise RuntimeError('service failed')
    engine.dispose.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_selected_database_does_not_fallback_to_redis(monkeypatch):
    monkeypatch.setenv('AUTH_SIWE_STORE', 'postgres')
    monkeypatch.delenv('AUTH_SIWE_DATABASE_URL', raising=False)
    monkeypatch.delenv('DATABASE_URL', raising=False)
    monkeypatch.delenv('DATABASE_URL_FILE', raising=False)
    monkeypatch.setenv('REDIS_URL', 'redis://must-not-be-used/0')
    async with nonce_runtime() as store: assert store is None


@pytest.mark.asyncio
async def test_driver_authentication_failure_is_redacted():
    from asyncpg import InvalidPasswordError
    engine = Engine()
    engine.execute = AsyncMock(side_effect=InvalidPasswordError('private password'))
    with pytest.raises(SiweStoreUnavailable, match='^SIWE nonce storage unavailable$'):
        await PostgresChallengeStore(engine).consume('person')


@pytest.mark.asyncio
@pytest.mark.parametrize('path', ['nonce', 'bind'])
async def test_http_database_failure_returns_503_without_binding(path, monkeypatch):
    import httpx
    from fastapi import FastAPI
    from auth_service import routes, wallet_bind
    from auth_service.deps import get_current_auth_user
    from auth_service.schemas import AuthMeResponse
    app = FastAPI(); app.include_router(routes.router, prefix='/auth')
    app.dependency_overrides[get_current_auth_user] = lambda: AuthMeResponse(sub='unit-person')
    app.dependency_overrides[routes.get_db_session] = lambda: AsyncMock()
    app.state.siwe_nonce_store = PostgresChallengeStore(Engine(fail=True))
    save = AsyncMock(); monkeypatch.setattr(wallet_bind, 'upsert_wallet_binding', save)
    body = {'address':'0x'+'11'*20} if path == 'nonce' else {'message':'unused', 'signature':'0x'+'11'*65}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://auth.test') as client:
        response = await client.post('/auth/siwe/'+path, json=body)
    assert response.status_code == 503, response.text
    assert 'private' not in response.text
    save.assert_not_awaited()

@pytest.mark.asyncio
async def test_database_url_file_and_legacy_values_are_not_logged(monkeypatch, tmp_path, caplog):
    from auth_service import database
    for name in ('AUTH_SIWE_DATABASE_URL','DATABASE_URL'):
        monkeypatch.delenv(name, raising=False)
    secret = tmp_path/'database-url'
    secret.write_text('postgresql://user:secret@db/owner\n')
    monkeypatch.setenv('DATABASE_URL_FILE', str(secret))
    monkeypatch.setenv('AUTH_SIWE_REDIS_URL', 'redis://private-secret@old')
    engine = Engine()
    monkeypatch.setattr(database, 'create_async_engine', lambda url, **kw: engine)
    async with nonce_runtime() as store:
        assert isinstance(store, PostgresChallengeStore)
    assert 'AUTH_SIWE_REDIS_URL' in caplog.text
    assert 'private-secret' not in caplog.text
    engine.dispose.assert_awaited_once()


def test_no_redis_import_or_configuration_value_reads():
    import ast
    from pathlib import Path
    root = Path(__file__).parents[1]
    for source in root.joinpath('src/auth_service').glob('*.py'):
        tree = ast.parse(source.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not alias.name.startswith('redis') for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or '').startswith('redis')
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr=='get':
                assert not any(isinstance(arg,ast.Constant) and arg.value in ('REDIS_URL','AUTH_SIWE_REDIS_URL') for arg in node.args)
    for name in ('pyproject.toml','core/auth-service/pyproject.toml'):
        assert '"redis>=' not in root.joinpath(name).read_text()


def test_owner_migration_fixture_matches_packaged_source():
    from pathlib import Path
    root=Path(__file__).parents[1]
    migrations = root / "src/auth_service/migrations"
    fixtures = root / "tests/fixtures"
    for folder in ("siwe", "auth-budget"):
        for fixture in (fixtures / folder).glob("*.sql"):
            assert (migrations / fixture.name).read_bytes() == fixture.read_bytes()
