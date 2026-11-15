"""Delivery retries retain a stable ID and never store a signature."""
from contextlib import asynccontextmanager
from datetime import UTC,datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
import uuid
import httpx
import pytest
from auth_service import wallet_commands,identity_owner
from auth_service.siwe_nonces import SiweStoreUnavailable
from auth_service.siwe import SiweError


class Engine:
    def __init__(self):
        self.deleted=False
        self.payload=dict(subject='person',email=None,wallet_address='0x'+'11'*20)
    @asynccontextmanager
    async def begin(self):
        try: yield self
        except BaseException:
            self.deleted=False
            raise
    async def execute(self,sql,params):
        if str(sql).startswith('DELETE'): self.deleted=True
        return SimpleNamespace(mappings=lambda:SimpleNamespace(one_or_none=lambda:{'payload':self.payload}))


@pytest.mark.asyncio
async def test_lost_response_retains_command_for_same_id_retry(monkeypatch):
    engine=Engine(); cid=uuid.uuid4()
    result=dict(command_id=str(cid),status='applied',binding=dict(keycloak_sub='person',email=None,wallet_address=engine.payload['wallet_address'],bound_at=datetime.now(UTC)))
    call=AsyncMock(side_effect=[httpx.ReadTimeout('private'),result])
    monkeypatch.setattr(identity_owner,'call',call)
    with pytest.raises(SiweStoreUnavailable): await wallet_commands.deliver(engine,cid)
    assert not engine.deleted
    bound=await wallet_commands.deliver(engine,cid)
    assert bound.keycloak_sub=='person' and engine.deleted
    assert call.call_args_list[0]==call.call_args_list[1]
    assert 'signature' not in call.call_args.kwargs


@pytest.mark.asyncio
async def test_definitive_rejection_removes_pending_command(monkeypatch):
    engine=Engine();cid=uuid.uuid4()
    monkeypatch.setattr(identity_owner,'call',AsyncMock(return_value={'command_id':str(cid),'status':'rejected'}))
    with pytest.raises(SiweError): await wallet_commands.deliver(engine,cid)
    assert engine.deleted


@pytest.mark.asyncio
async def test_old_or_inconsistent_owner_does_not_ack_command(monkeypatch):
    engine=Engine();cid=uuid.uuid4()
    monkeypatch.setattr(identity_owner,'call',AsyncMock(return_value={'status':'applied'}))
    with pytest.raises(SiweStoreUnavailable): await wallet_commands.deliver(engine,cid)
    assert not engine.deleted
