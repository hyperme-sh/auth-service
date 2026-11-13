"""Actual Auth producers and owner SQL in the central scheduled batch only."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from api.infrastructure.persistence.db_session import set_db_session, reset_db_session
from auth_service import outbox
from controlplane_events.contracts import validate_event_envelope
from controlplane_events.envelope import ControlPlaneEventEnvelope

PRODUCERS=['callback_login','callback_token','refresh','switch','smoke','host','organization','network']


@pytest.fixture
async def fixture(monkeypatch):
    path=Path(os.environ['AUTH_OUTBOX_FIXTURE_SCRIPT'])
    spec=importlib.util.spec_from_file_location('auth_outbox_fixture',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.environment(os.environ)
    def command(action): subprocess.run([sys.executable,str(path),action],check=True,timeout=90)
    command('reset-case')
    config=module.configuration()
    url=make_url((Path(os.environ['AUTH_OUTBOX_FIXTURE_DIR'])/'owner-url').read_text()).set(drivername='postgresql+asyncpg')
    engine=create_async_engine(url)
    try: yield module,command,config,async_sessionmaker(engine,expire_on_commit=False),module.configure_producers(monkeypatch)
    finally: await engine.dispose()


async def rows(maker,tenant):
    async with maker() as db:
        await db.execute(text("SELECT set_config('app.current_tenant_id',:tenant,true)"),{'tenant':tenant})
        issues=(await db.execute(text('SELECT token_sha256 FROM auth_token_issuance'))).scalars().all()
        events=(await db.execute(text('SELECT envelope FROM service_outbox'))).scalars().all()
        return issues,events


@pytest.mark.parametrize('producer',PRODUCERS)
@pytest.mark.parametrize('outcome',['commit','rollback','insert_failure','retry'])
async def test_auth_transaction(producer,outcome,fixture,monkeypatch):
    module,command,config,maker,invoke=fixture
    if outcome=='insert_failure': command('break-outbox')
    original=outbox.publish_auth_event
    if outcome=='retry':
        async def duplicate(**kw):
            first=await original(**kw)
            assert await original(**kw)==first
            return first
        monkeypatch.setattr(outbox,'publish_auth_event',duplicate)
    async with maker() as session:
        token=set_db_session(session)
        try:
            if outcome=='insert_failure':
                from sqlalchemy.exc import IntegrityError
                with pytest.raises(IntegrityError): await invoke(producer)
                await session.rollback()
            else:
                response=await invoke(producer)
                assert getattr(response,'status_code',200)==200
                if outcome=='rollback': await session.rollback()
                else: await session.commit()
        finally: reset_db_session(token)
    issues,events=await rows(maker,config['tenant_id'])
    committed=outcome in ('commit','retry')
    assert len(issues)==int(committed)
    assert len(events)==((2 if producer.startswith('callback') else 1) if committed else 0)
    assert all(len(digest)==64 for digest in issues)
    for encoded in events:
        envelope=ControlPlaneEventEnvelope.model_validate(encoded)
        validate_event_envelope(envelope)
        assert envelope.tenant_id==uuid.UUID(config['tenant_id'])
        assert 'access_token' not in encoded['payload']
    assert await rows(maker,config['other_tenant_id'])==([],[])


async def test_callback_second_event_failure_rolls_back_first_and_issuance(fixture,monkeypatch):
    module,command,config,maker,invoke=fixture
    original=outbox.publish_auth_event
    calls=0
    async def fail_second(**kw):
        nonlocal calls
        calls+=1
        if calls==2:
            # Actual SQL failure in the same transaction after the first event.
            await outbox.get_db_session().execute(text('SELECT 1/0'))
        return await original(**kw)
    monkeypatch.setattr(outbox,'publish_auth_event',fail_second)
    async with maker() as session:
        token=set_db_session(session)
        try:
            from sqlalchemy.exc import DBAPIError
            with pytest.raises(DBAPIError): await invoke('callback_token')
            await session.rollback()
        finally: reset_db_session(token)
    assert calls==2
    assert await rows(maker,config['tenant_id'])==([],[])
