"""Durable first binding and exact output; no overwrite or expired-row deletion."""
import asyncio
import json
from sqlalchemy import text
from auth_service import first_oidc_link as core
from auth_service.nightly_runtime import admission
from auth_service.nightly_store import PostgresNightlyStore


class FirstOidcStore:
    def __init__(self, engine):self.engine=engine

    async def issue(self, record, token, binding, provider_jwks, signer, signer_key, current):
        # Credential identity is independent of client, signer rotation and config.
        identity=core.fingerprint(dict(iss=binding['issuer'],tenant=binding['tenant'],sub=binding['subject']))
        bound=admission.get()
        async with asyncio.timeout(10):
            async with self.engine.begin() as db:
                if bound is not None:await PostgresNightlyStore(self.engine).assert_pending(db,bound)
                await db.execute(text('SELECT pg_advisory_xact_lock(hashtextextended(:identity,0))'),{'identity':identity})
                current()
                now=int(await db.scalar(text('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint')))
                _,_,digest=core.validate(record,token,binding,provider_jwks,signer,signer_key,now)
                row=(await db.execute(text('SELECT principal,output FROM auth_first_oidc_link WHERE credential=:identity'),{'identity':identity})).mappings().one_or_none()
                if row is not None:
                    core.require(row['principal']==binding['principal'])
                    result=core.replay(row['output'],digest,binding['principal'],now)
                else:
                    cancelled=await db.scalar(text('SELECT 1 FROM auth_first_oidc_cancel WHERE credential=:identity AND nonce=:nonce'),{'identity':identity,'nonce':record['nonce']})
                    core.require(cancelled is None)
                    output=core.issue(record,token,binding,provider_jwks,signer,signer_key,now)
                    await db.execute(text('INSERT INTO auth_first_oidc_link(credential,principal,output) VALUES(:identity,:principal,CAST(:output AS jsonb))'),
                        {'identity':identity,'principal':binding['principal'],'output':json.dumps(output,separators=(',',':'))})
                    result=output['attestation']
                current()
                if bound is not None:await PostgresNightlyStore(self.engine).assert_pending(db,bound)
                committed_at=int(await db.scalar(text('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint')))
                core.validate(record,token,binding,provider_jwks,signer,signer_key,committed_at)
            return result

    async def cancel(self, record, binding, current):
        identity=core.fingerprint(dict(iss=binding['issuer'],tenant=binding['tenant'],sub=binding['subject']))
        bound=admission.get()
        async with asyncio.timeout(10):
            async with self.engine.begin() as db:
                if bound is not None:await PostgresNightlyStore(self.engine).assert_pending(db,bound)
                await db.execute(text('SELECT pg_advisory_xact_lock(hashtextextended(:identity,0))'),{'identity':identity})
                current()
                now=int(await db.scalar(text('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint')))
                core.prepare(record,binding,now)
                existing=await db.scalar(text('SELECT principal FROM auth_first_oidc_link WHERE credential=:identity'),{'identity':identity})
                if existing is not None:
                    core.require(existing==binding['principal'])
                    current()
                    if bound is not None:await PostgresNightlyStore(self.engine).assert_pending(db,bound)
                    core.prepare(record,binding,int(await db.scalar(text('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint'))))
                    return 'already-issued'
                await db.execute(text('DELETE FROM auth_first_oidc_cancel WHERE expires_at<=:now'),{'now':now})
                count=await db.scalar(text('SELECT count(*) FROM auth_first_oidc_cancel WHERE credential=:identity'),{'identity':identity})
                core.require(count<128)
                await db.execute(text('INSERT INTO auth_first_oidc_cancel(credential,nonce,expires_at) VALUES(:identity,:nonce,:expires) ON CONFLICT DO NOTHING'),
                    {'identity':identity,'nonce':record['nonce'],'expires':min(record['issuedAt']+120,binding['expiresAt'])})
                current()
                if bound is not None:await PostgresNightlyStore(self.engine).assert_pending(db,bound)
                core.prepare(record,binding,int(await db.scalar(text('SELECT floor(extract(epoch FROM clock_timestamp()))::bigint'))))
            return 'cancelled'
