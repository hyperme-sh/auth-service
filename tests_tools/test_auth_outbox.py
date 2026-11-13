"""Offline transaction/producer contracts; SQL combinations run in nightly."""
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid
import pytest
from auth_service import outbox
from controlplane_api.event_types import AUTH_TOKEN_ISSUED_V1

TENANT=uuid.UUID('00000000-0000-4000-8000-000000009501')
PAYLOAD={'subject':'unit-person','grant_type':'refresh_token','client_id':'unit-client'}


class Session:
    def __init__(self, fail=False): self.calls=[]; self.fail=fail; self.events={}; self.issues={}
    async def execute(self, statement, params):
        sql=str(statement); self.calls.append((sql,params))
        result=None
        if sql.startswith('INSERT INTO auth_token_issuance'):
            self.issues[params['id']]=params
        elif sql.startswith('INSERT INTO service_outbox'):
            if self.fail: raise RuntimeError('insert refused')
            if params['id'] not in self.events:
                self.events[params['id']]=params['envelope']; result=params['id']
        elif sql.startswith('SELECT envelope'):
            result=self.events[params['id']]
        return SimpleNamespace(scalar_one_or_none=lambda:result,scalar_one=lambda:result)


@pytest.mark.asyncio
async def test_retry_uses_same_session_and_operation_without_storing_token(monkeypatch):
    session=Session();monkeypatch.setattr(outbox,'get_db_session',lambda:session)
    for _ in range(2): await outbox.publish_auth_event(token='secret-bearer',tenant_id=TENANT,event_type=AUTH_TOKEN_ISSUED_V1,payload=PAYLOAD)
    assert len(session.issues)==len(session.events)==1
    assert 'secret-bearer' not in str(session.calls)
    assert len(next(iter(session.issues.values()))['digest'])==64


@pytest.mark.asyncio
async def test_insert_failure_propagates_to_request_transaction(monkeypatch):
    session=Session(fail=True);monkeypatch.setattr(outbox,'get_db_session',lambda:session)
    with pytest.raises(RuntimeError,match='insert refused'):
        await outbox.publish_auth_event(token='secret-bearer',tenant_id=TENANT,event_type=AUTH_TOKEN_ISSUED_V1,payload=PAYLOAD)
    assert not session.events


@pytest.mark.asyncio
async def test_retry_with_changed_event_payload_refuses(monkeypatch):
    session=Session();monkeypatch.setattr(outbox,'get_db_session',lambda:session)
    await outbox.publish_auth_event(token='same-token',tenant_id=TENANT,event_type=AUTH_TOKEN_ISSUED_V1,payload=PAYLOAD)
    with pytest.raises(ValueError,match='conflicts'):
        await outbox.publish_auth_event(token='same-token',tenant_id=TENANT,event_type=AUTH_TOKEN_ISSUED_V1,payload=dict(PAYLOAD,subject='other'))


def test_all_eight_producers_use_transactional_owner_helper():
    root=Path(__file__).resolve().parents[1]/'src/auth_service'
    expected={'routes.py':6,'network_session.py':1,'scoped_session.py':1}
    for name,count in expected.items():
        tree=ast.parse((root/name).read_text())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='publish_auth_event']
        assert len(calls)==count
        assert all({'token','tenant_id','event_type','payload'} <= {kw.arg for kw in n.keywords} for n in calls)
    for path in root.rglob('*.py'):
        source=path.read_text()
        assert 'get_tenant_event_publisher' not in source
        assert 'PostgresEventPublisher' not in source
        assert 'ServiceBus' not in source
        assert not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='publish' for n in ast.walk(ast.parse(source)))


@pytest.mark.asyncio
@pytest.mark.parametrize('status',[200,400,503])
async def test_request_commits_success_and_rolls_back_error_responses(monkeypatch,status):
    from auth_service.transaction import AuthTransactionMiddleware
    from api.interfaces.middlewares import database_middleware as shared
    from starlette.requests import Request
    from starlette.responses import Response
    session=AsyncMock()
    session.__aenter__.return_value=session
    monkeypatch.setattr(shared,'get_session_maker',lambda:lambda:session)
    monkeypatch.setattr(shared,'is_tenancy_enabled',lambda:False)
    request=Request({'type':'http','headers':[]}); request.state.tenant_id=None
    async def reply(request): return Response(status_code=status)
    result=await AuthTransactionMiddleware(None).dispatch(request,reply)
    assert result.status_code==status
    assert session.commit.await_count==(status<400)
    assert session.rollback.await_count==(status>=400)
