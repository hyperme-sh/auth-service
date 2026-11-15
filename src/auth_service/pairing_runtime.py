"""Explicit bounded scope configuration and owner-database runtime."""
import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from auth_service.pairing_wire import scope, scope_key
from auth_service.pairing_store import PostgresPairingStore, PairingUnavailable

logger = logging.getLogger(__name__)


def read_scopes():
    path = os.environ.get('AUTH_SEA_PAIRING_SCOPES_FILE')
    if path is None: return ()
    try:
        with Path(path).open('rb') as stream: raw = stream.read(32769)
        if len(raw) > 32768: raise ValueError()
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {'version','scopes'} or type(value['version']) is not int or value['version'] != 1: raise ValueError()
        rows = value['scopes']
        if type(rows) is not list or not 1 <= len(rows) <= 8: raise ValueError()
        for row in rows: scope(row)
        if len({scope_key(row) for row in rows}) != len(rows): raise ValueError()
        return tuple(rows)
    except Exception: raise ValueError('Invalid pairing scope configuration') from None


@asynccontextmanager
async def pairing_runtime():
    scopes = read_scopes()
    if not scopes:
        yield None, (); return
    from sqlalchemy.ext.asyncio import create_async_engine
    from controlplane_api.config import settings
    from controlplane_db.session import normalize_database_url
    url = normalize_database_url(settings.database_url)
    if not url.startswith('postgresql+asyncpg://'): raise ValueError('Pairing requires Auth PostgreSQL')
    engine = create_async_engine(url, pool_pre_ping=True)
    store = PostgresPairingStore(engine)
    async def sweep():
        while True:
            try: await store.cleanup_all()
            except PairingUnavailable: logger.warning('Pairing cleanup unavailable')
            await asyncio.sleep(30)
    task = asyncio.create_task(sweep())
    try: yield store, scopes
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError): await task
        await engine.dispose()
