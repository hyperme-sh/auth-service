"""PostgreSQL challenge storage with independent, committed consume-once writes."""
import asyncio
import hashlib
import json
from asyncpg import PostgresError
from collections.abc import Mapping
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError
from auth_service.siwe import SiweError
from auth_service.siwe_nonces import SiweStoreUnavailable, TTL_SECONDS

_PUT = text("""
INSERT INTO auth_siwe_challenges(subject_hash, challenge, expires_at)
VALUES (:subject, :challenge, clock_timestamp() + :ttl * interval '1 second')
ON CONFLICT (subject_hash) DO UPDATE
SET challenge=EXCLUDED.challenge, expires_at=EXCLUDED.expires_at
""").bindparams(bindparam('challenge', type_=JSONB))
_CONSUME = text("""
DELETE FROM auth_siwe_challenges WHERE subject_hash=:subject
RETURNING challenge, expires_at > clock_timestamp() AS usable
""")
_CLEANUP = text("""
DELETE FROM auth_siwe_challenges WHERE subject_hash IN (
  SELECT subject_hash FROM auth_siwe_challenges
  WHERE expires_at <= clock_timestamp() ORDER BY expires_at
  LIMIT 1000 FOR UPDATE SKIP LOCKED
)
""")


class PostgresChallengeStore:
    def __init__(self, engine):
        self.engine = engine

    @staticmethod
    def key(subject: str) -> str:
        return hashlib.sha256(subject.encode()).hexdigest()

    async def put(self, subject: str, challenge: Mapping) -> None:
        # Round-trip before binding so both adapters accept the same JSON values.
        value = json.loads(json.dumps(dict(challenge)))
        try:
            async with asyncio.timeout(5):
                async with self.engine.begin() as connection:
                    await connection.execute(_CLEANUP)
                    await connection.execute(_PUT, {'subject': self.key(subject), 'challenge': value, 'ttl': TTL_SECONDS})
        except (SQLAlchemyError, PostgresError, OSError, TimeoutError) as exc:
            raise SiweStoreUnavailable('SIWE nonce storage unavailable') from exc

    async def consume(self, subject: str) -> dict:
        try:
            async with asyncio.timeout(5):
                async with self.engine.begin() as connection:
                    row = (await connection.execute(_CONSUME, {'subject': self.key(subject)})).mappings().one_or_none()
        except (SQLAlchemyError, PostgresError, OSError, TimeoutError) as exc:
            raise SiweStoreUnavailable('SIWE nonce storage unavailable') from exc
        # The deletion is committed before signature verification or any bind
        # transaction. Invalid, expired and malformed challenges stay consumed.
        if row is None or not row['usable']:
            raise SiweError('SIWE nonce is missing or expired; request a new nonce')
        if not isinstance(row['challenge'], dict):
            raise SiweStoreUnavailable('SIWE nonce storage returned invalid data')
        return row['challenge']

    async def expire(self, subject: str) -> None:
        try:
            async with asyncio.timeout(5):
                async with self.engine.begin() as connection:
                    await connection.execute(text('DELETE FROM auth_siwe_challenges WHERE subject_hash=:subject'), {'subject': self.key(subject)})
        except (SQLAlchemyError, PostgresError, OSError, TimeoutError) as exc:
            raise SiweStoreUnavailable('SIWE nonce storage unavailable') from exc
