"""Subject-owned SIWE challenges in the Auth PostgreSQL database."""

import asyncio
import logging
import os
from collections.abc import Mapping
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

TTL_SECONDS = 600
logger = logging.getLogger(__name__)


class SiweStoreUnavailable(RuntimeError):
    """Nonce storage failed; never fall back to process-local authorization state."""


class ChallengeStore(Protocol):
    async def put(self, subject: str, challenge: Mapping) -> None: ...
    async def peek(self, subject: str) -> dict: ...
    async def failed(self, subject: str, nonce: str) -> None: ...
    async def enqueue(self, subject: str, nonce: str, payload: dict): ...
    async def expire(self, subject: str) -> None: ...


async def _cleanup(store):
    while True:
        try:
            await store.cleanup()
        except SiweStoreUnavailable:
            logger.warning('SIWE challenge cleanup temporarily unavailable')
        await asyncio.sleep(60)


async def _delivery(store):
    from auth_service.wallet_commands import drain
    while True:
        try:
            await drain(store.engine)
        except SiweStoreUnavailable:
            logger.warning('Wallet binding queue temporarily unavailable')
        await asyncio.sleep(10)


@asynccontextmanager
async def nonce_runtime():
    for name in ('AUTH_SIWE_STORE', 'AUTH_SIWE_REDIS_URL', 'REDIS_URL'):
        if name in os.environ:
            logger.warning('%s is ignored; SIWE uses Auth PostgreSQL', name)
    url = os.environ.get('AUTH_SIWE_DATABASE_URL') or os.environ.get('DATABASE_URL', '')
    if not url and os.environ.get('DATABASE_URL_FILE'):
        url = Path(os.environ['DATABASE_URL_FILE']).read_text().strip()
    if not url:
        yield None
        return
    parsed = urlsplit(url)
    if parsed.scheme not in {'postgresql', 'postgresql+asyncpg', 'postgresql+psycopg'} or not parsed.hostname:
        raise ValueError('SIWE requires a PostgreSQL service URL')
    from sqlalchemy.ext.asyncio import create_async_engine
    from controlplane_db.session import normalize_database_url
    from auth_service.siwe_postgres import PostgresChallengeStore
    engine = create_async_engine(normalize_database_url(url), pool_pre_ping=True)
    tasks = []
    try:
        store = PostgresChallengeStore(engine)
        tasks = [asyncio.create_task(_cleanup(store)), asyncio.create_task(_delivery(store))]
        yield store
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with suppress(asyncio.CancelledError):
                await task
        await engine.dispose()
