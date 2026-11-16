"""PostgreSQL authority shared by serving owners, with no cache or local fallback."""
import asyncio
import copy
import json
from sqlalchemy import text
from auth_service import nightly_state as state


class PostgresNightlyStore:
    def __init__(self, engine, scopes=None): self.engine, self.scopes = engine, scopes

    async def command(self, value):
        state.command(value)
        try:
            async with asyncio.timeout(8), self.engine.begin() as db:
                await db.execute(text("SET LOCAL statement_timeout = '5000ms'"))
                if value['action'] == 'register':
                    row = state.create(value)
                    await db.execute(text('INSERT INTO auth_nightly_run(owner,run,grant_hash,state) '
                        'VALUES(:owner,:run,:grant,CAST(:state AS jsonb)) ON CONFLICT (owner,run) DO NOTHING'),
                        dict(owner=row['owner'], run=row['run'], grant=row['grant_hash'], state=json.dumps(row)))
                if value['action'] == 'admit':
                    query = 'SELECT state FROM auth_nightly_run WHERE owner=:owner AND grant_hash=:grant FOR UPDATE'
                    params = dict(owner=value['owner'], grant=state.digest(value['grant']))
                else:
                    query = 'SELECT state FROM auth_nightly_run WHERE owner=:owner AND run=:run FOR UPDATE'
                    params = dict(owner=value['owner'], run=value['run'])
                raw = (await db.execute(text(query), params)).scalar_one_or_none()
                state.require(raw is not None)
                row = copy.deepcopy(raw)
                if self.scopes is not None: state.require(self.scopes.get(row['scope']['suite']) == row['scope'])
                result = state.apply(row, value)
                await db.execute(text('UPDATE auth_nightly_run SET state=CAST(:state AS jsonb) WHERE owner=:owner AND run=:run'),
                                 dict(owner=row['owner'], run=row['run'], state=json.dumps(row, separators=(',', ':'), allow_nan=False)))
            return result
        except Exception: raise state.Refused() from None

    async def assert_pending(self, db, binding):
        """Serialize a native Auth commit with its owner barrier in the same DB transaction."""
        raw = (await db.execute(text('SELECT state FROM auth_nightly_run WHERE owner=:owner AND run=:run FOR UPDATE'),
                               dict(owner='auth', run=binding['run']))).scalar_one_or_none()
        state.require(raw is not None); state.validate(raw)
        state.require(raw['generation'] == binding['generation'] and raw['scope'] == binding['scope']
                      and raw['phase'] != 'terminal' and raw['operations'].get(binding['operation']) == 'pending')
