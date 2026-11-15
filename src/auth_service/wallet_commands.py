"""Retry durable binding commands without sharing the User database."""
import asyncio
import httpx
from asyncpg import PostgresError
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from auth_service.siwe import SiweError
from auth_service.siwe_nonces import SiweStoreUnavailable


async def deliver(engine, command_id):
    from auth_service.identity_owner import call
    from auth_service.wallet_bind import WalletBinding
    result = None
    rejected = False
    try:
        async with asyncio.timeout(15):
            async with engine.begin() as db:
                row = (await db.execute(text('SELECT payload FROM auth_wallet_commands WHERE id=:id FOR UPDATE'),
                                        {'id': command_id})).mappings().one_or_none()
                if row is None:
                    raise SiweStoreUnavailable('Wallet binding delivery completed; check current binding')
                payload = row['payload']
                response = await call('bind-wallet', command_id=str(command_id), **payload)
                if not isinstance(response, dict) or response.get('command_id') != str(command_id):
                    raise SiweStoreUnavailable('Wallet owner command contract unavailable')
                if response.get('status') == 'applied':
                    result = TypeAdapter(WalletBinding).validate_python(response.get('binding'))
                    if (result.keycloak_sub != payload['subject'] or result.email != payload['email']
                            or result.wallet_address != payload['wallet_address']):
                        raise SiweStoreUnavailable('Wallet owner returned an inconsistent binding')
                elif response.get('status') == 'rejected':
                    rejected = True
                else:
                    raise SiweStoreUnavailable('Wallet owner command result unavailable')
                # The owner retained the idempotency decision. Remove the pending
                # payload here so Auth does not retain completed personal records.
                await db.execute(text('DELETE FROM auth_wallet_commands WHERE id=:id'), {'id': command_id})
    except (SQLAlchemyError, PostgresError, OSError, TimeoutError, httpx.HTTPError, ValidationError, RuntimeError, ValueError) as exc:
        raise SiweStoreUnavailable('Wallet binding delivery temporarily unavailable') from exc
    if rejected:
        raise SiweError('Wallet binding was rejected; request a new nonce')
    return result


async def drain(engine):
    try:
        async with engine.connect() as db:
            ids = (await db.execute(text('SELECT id FROM auth_wallet_commands ORDER BY created_at LIMIT 100'))).scalars().all()
        for command_id in ids:
            try:
                await deliver(engine, command_id)
            except (SiweError, SiweStoreUnavailable):
                pass
    except (SQLAlchemyError, PostgresError, OSError, TimeoutError) as exc:
        raise SiweStoreUnavailable('Wallet binding queue unavailable') from exc
