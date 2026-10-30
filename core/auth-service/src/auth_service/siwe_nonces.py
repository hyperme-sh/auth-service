"""Shared, expiring subject-owned SIWE challenges with atomic consumption."""

import asyncio
import hashlib
import json
import os
from collections.abc import Mapping
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from redis.asyncio import Redis
from redis.exceptions import RedisError

from auth_service.siwe import SiweError

TTL_SECONDS = 600


class SiweStoreUnavailable(RuntimeError):
    """Nonce storage failed; never fall back to process-local authorization state."""


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


@asynccontextmanager
async def nonce_runtime():
    url = os.environ.get("AUTH_SIWE_REDIS_URL") or os.environ.get("REDIS_URL", "")
    if not url:
        yield None
        return
    parsed = urlsplit(url)
    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
        raise ValueError("AUTH_SIWE_REDIS_URL requires a Redis service URL")
    async with Redis.from_url(url, socket_timeout=5, socket_connect_timeout=5) as redis:
        yield SiweNonceStore(redis)
