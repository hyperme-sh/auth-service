"""Durable, scope-locked PostgreSQL relay authority; no in-memory fallback."""
import asyncio
import copy
import json
from asyncpg import PostgresError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from auth_service.pairing_state import apply, cleanup, empty
from auth_service.pairing_wire import scope_key


class PairingUnavailable(RuntimeError): pass


class PostgresPairingStore:
    def __init__(self, engine): self.engine = engine

    async def _transaction(self, scope, operation=None):
        key = scope_key(scope)
        try:
            async with asyncio.timeout(5):
                async with self.engine.begin() as db:
                    from auth_service.nightly_runtime import admission
                    from auth_service.nightly_store import PostgresNightlyStore
                    bound = admission.get()
                    if bound is not None:
                        await PostgresNightlyStore(self.engine).assert_pending(db, bound)
                    # A fixed configured scope has one authority row. This locks
                    # quotas, transitions and cleanup together across workers.
                    await db.execute(text('INSERT INTO auth_sea_pairing(scope_id,state) VALUES(:id,CAST(:state AS jsonb)) ON CONFLICT DO NOTHING'),
                        {'id':key,'state':json.dumps(empty())})
                    raw = (await db.execute(text('SELECT state FROM auth_sea_pairing WHERE scope_id=:id FOR UPDATE'), {'id':key})).scalar_one()
                    state = copy.deepcopy(raw)
                    if type(state) is not dict or state.get('version') != 1: raise PairingUnavailable()
                    if operation is not None:
                        existing = state['sessions'].get(operation['session'])
                        original = None if bound is None else {k:bound[k] for k in ('run','generation')}
                        if existing is not None and existing.get('nightly_run') != original:
                            raise PairingUnavailable()
                    now = int(await db.scalar(text('SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint')))
                    if operation is None:
                        cleanup(state, now); result = (200, None)
                    else: result = apply(state, scope=scope, now=now, **operation)
                    if bound is not None and operation is not None and result[0] < 400:
                        created = state['sessions'].get(operation['session'])
                        if created is not None: created['nightly_run'] = original
                    await db.execute(text('UPDATE auth_sea_pairing SET state=CAST(:state AS jsonb) WHERE scope_id=:id'),
                        {'id':key,'state':json.dumps(state, separators=(',', ':'), allow_nan=False)})
                return result
        except (SQLAlchemyError, PostgresError, OSError, TimeoutError, ValueError, TypeError, KeyError) as exc:
            raise PairingUnavailable('Pairing storage unavailable') from exc

    async def execute(self, scope, **operation): return await self._transaction(scope, operation)
    async def cleanup(self, scope): await self._transaction(scope)

    async def cleanup_all(self):
        """Sweep retained rows even after their scope is removed from configuration."""
        try:
            async with asyncio.timeout(5):
                async with self.engine.begin() as db:
                    rows = (await db.execute(text('SELECT scope_id,state FROM auth_sea_pairing ORDER BY swept_at LIMIT 8 FOR UPDATE SKIP LOCKED'))).mappings().all()
                    now = int(await db.scalar(text('SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint')))
                    for row in rows:
                        state = copy.deepcopy(row['state'])
                        cleanup(state, now)
                        if not state['sessions'] and state['window'] < now // 60000:
                            await db.execute(text('DELETE FROM auth_sea_pairing WHERE scope_id=:id'), {'id':row['scope_id']})
                        else:
                            await db.execute(text('UPDATE auth_sea_pairing SET state=CAST(:state AS jsonb),swept_at=clock_timestamp() WHERE scope_id=:id'),
                                {'id':row['scope_id'],'state':json.dumps(state, separators=(',', ':'), allow_nan=False)})
        except (SQLAlchemyError, PostgresError, OSError, TimeoutError, ValueError, TypeError, KeyError) as exc:
            raise PairingUnavailable('Pairing cleanup unavailable') from exc
