"""Own the PostgreSQL connection budget for one Auth process."""
from contextlib import AsyncExitStack, asynccontextmanager
import os

from controlplane_db.session import normalize_database_url
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine


@asynccontextmanager
async def runtime_engines(owner_url: str | None, nonce_url: str | None):
    owner = make_url(normalize_database_url(owner_url)) if owner_url else None
    nonce = make_url(normalize_database_url(nonce_url)) if nonce_url else None
    urls = dict.fromkeys(url for url in (owner, nonce) if url is not None)
    limit = os.environ.get("AUTH_DB_POOL_LIMIT", "2")
    if limit not in {"1", "2"} or len(urls) > int(limit):
        raise ValueError("Auth requires one or two PostgreSQL connections across its configured databases")
    # The default shares both slots. A separate, explicitly configured SIWE
    # database retains one slot on each database within the same process cap.
    async with AsyncExitStack() as stack:
        engines = {}
        for url in urls:
            engine = create_async_engine(
                url, pool_size=int(limit) // len(urls), max_overflow=0, pool_pre_ping=True,
            )
            stack.push_async_callback(engine.dispose)
            engines[url] = engine
        yield engines.get(owner), engines.get(nonce)
