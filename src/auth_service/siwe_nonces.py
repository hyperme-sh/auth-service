"""Shared, expiring subject-owned SIWE challenges with atomic consumption."""

import asyncio
import hashlib
import json
import os
from collections.abc import Mapping
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from typing import Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

from auth_service.siwe import SiweError

TTL_SECONDS = 600


class SiweStoreUnavailable(RuntimeError):
    """Nonce storage failed; never fall back to process-local authorization state."""


class ChallengeStore(Protocol):
    async def put(self, subject: str, challenge: Mapping) -> None: ...
    async def consume(self, subject: str) -> dict: ...
    async def expire(self, subject: str) -> None: ...


class SiweNonceStore:
    def __init__(self, redis: Redis):
        self.redis = redis

    @staticmethod
    def key(subject: str) -> str:
        # Do not expose subjects in Redis keys; one outstanding challenge per person.
        return "auth:siwe-nonce:v1:" + hashlib.sha256(subject.encode()).hexdigest()

    async def put(self, subject: str, challenge: Mapping) -> None:
        try:
            async with asyncio.timeout(5):
                await self.redis.set(
                    self.key(subject), json.dumps(dict(challenge)), ex=TTL_SECONDS
                )
        except (RedisError, TimeoutError) as exc:
            raise SiweStoreUnavailable("SIWE nonce storage unavailable") from exc

    async def consume(self, subject: str) -> dict:
        try:
            async with asyncio.timeout(5):
                raw = await self.redis.getdel(self.key(subject))
        except (RedisError, TimeoutError) as exc:
            raise SiweStoreUnavailable("SIWE nonce storage unavailable") from exc
        if raw is None:
            raise SiweError("SIWE nonce is missing or expired; request a new nonce")
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise TypeError("Invalid stored challenge")
            return value
        except (ValueError, TypeError) as exc:
            raise SiweStoreUnavailable(
                "SIWE nonce storage returned invalid data"
            ) from exc


    async def expire(self, subject: str) -> None:
        try:
            async with asyncio.timeout(5):
                await self.redis.delete(self.key(subject))
        except (RedisError, TimeoutError) as exc:
            raise SiweStoreUnavailable("SIWE nonce storage unavailable") from exc


RedisChallengeStore = SiweNonceStore


@asynccontextmanager
async def nonce_runtime():
    backend = os.environ.get("AUTH_SIWE_STORE", "redis").strip().lower()
    if backend not in {"redis", "postgres"}:
        raise ValueError("AUTH_SIWE_STORE must be redis or postgres")
    if backend == "postgres":
        url = os.environ.get("AUTH_SIWE_DATABASE_URL") or os.environ.get("DATABASE_URL", "")
        if not url:
            yield None
            return
        parsed = urlsplit(url)
        if parsed.scheme not in {"postgresql", "postgresql+asyncpg", "postgresql+psycopg"} or not parsed.hostname:
            raise ValueError("AUTH_SIWE_DATABASE_URL requires a PostgreSQL service URL")
        from sqlalchemy.ext.asyncio import create_async_engine
        from controlplane_db.session import normalize_database_url
        from auth_service.siwe_postgres import PostgresChallengeStore
        engine = create_async_engine(normalize_database_url(url), pool_pre_ping=True)
        try:
            yield PostgresChallengeStore(engine)
        finally:
            await engine.dispose()
        return
    url = os.environ.get("AUTH_SIWE_REDIS_URL") or os.environ.get("REDIS_URL", "")
    if not url:
        yield None
        return
    parsed = urlsplit(url)
    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
        raise ValueError("AUTH_SIWE_REDIS_URL requires a Redis service URL")
    async with Redis.from_url(url, socket_timeout=5, socket_connect_timeout=5) as redis:
        yield SiweNonceStore(redis)
