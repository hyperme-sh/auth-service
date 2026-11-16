"""Bounded PostgreSQL proof attempts; transition before external code exchange."""
import asyncio
import copy
import json
from sqlalchemy import text
from auth_service import linked_oidc_state as state


class LinkedOidcStore:
    def __init__(self, engine):
        self.engine = engine

    async def execute(self, provider, challenge, run, operation):
        domain = state.fingerprint(provider)
        key = state.fingerprint(challenge)
        async with asyncio.timeout(5):
            async with self.engine.begin() as db:
                from auth_service.nightly_runtime import admission
                from auth_service.nightly_store import PostgresNightlyStore
                bound = admission.get()
                actual_run = None if bound is None else {k:bound[k] for k in ('run','generation')}
                state.require(actual_run == run)
                if bound is not None:
                    await PostgresNightlyStore(self.engine).assert_pending(db, bound)
                await db.execute(text('DELETE FROM auth_linked_oidc WHERE expires_at <= floor(extract(epoch FROM clock_timestamp()))'))
                await db.execute(text('INSERT INTO auth_linked_oidc(domain,state,expires_at) VALUES(:domain,CAST(:state AS jsonb),floor(extract(epoch FROM clock_timestamp()))+300) ON CONFLICT DO NOTHING'),
                    {'domain':domain,'state':'{}'})
                rows = copy.deepcopy((await db.execute(text('SELECT state FROM auth_linked_oidc WHERE domain=:domain FOR UPDATE'), {'domain':domain})).scalar_one())
                state.require(type(rows) is dict)
                now = int(await db.scalar(text('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint')))
                rows = {k:v for k,v in rows.items() if v['challenge']['expiresAt'] > now}
                result = operation(rows, key, now)
                state.require(len(rows) <= 128)
                await db.execute(text('UPDATE auth_linked_oidc SET state=CAST(:state AS jsonb),expires_at=:expires WHERE domain=:domain'),
                    {'domain':domain,'state':json.dumps(rows,separators=(',', ':'),allow_nan=False),'expires':max((v['challenge']['expiresAt'] for v in rows.values()),default=now)})
                if bound is not None:
                    await PostgresNightlyStore(self.engine).assert_pending(db, bound)
                committed_at = int(await db.scalar(text('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint')))
                state.challenge(challenge, provider, committed_at)
            return result
