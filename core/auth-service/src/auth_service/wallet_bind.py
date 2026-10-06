"""Bind one recovered SIWE address onto the identified Keycloak person."""

from __future__ import annotations

import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from controlplane_db.models import UserWalletBinding
from controlplane_identity.wallet import BaseWalletVerifier, CounterfactualValidator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.schemas import AuthMeResponse
from auth_service.siwe import (
    SIWE_DOMAIN,
    SIWE_STATEMENT,
    SIWE_URI,
    SIWE_VERSION,
    SiweError,
    build_siwe_message,
    checksum_address,
    configured_chain_id,
    verify_siwe_bind,
)

_NONCE_TTL_SECONDS = 600
_nonces: dict[str, tuple[SiweNonce, float]] = {}


@dataclass(frozen=True, slots=True)
class SiweNonce:
    nonce: str
    issued_at: str
    domain: str
    uri: str
    statement: str
    version: str
    chain_id: int
    message: str


@dataclass(frozen=True, slots=True)
class WalletBinding:
    keycloak_sub: str
    email: str | None
    wallet_address: str
    bound_at: datetime


def issue_siwe_nonce(
    user: AuthMeResponse,
    *,
    address: str,
    chain_id: int | None = None,
    now: datetime | None = None,
) -> SiweNonce:
    if not user.sub or not str(user.sub).strip():
        raise SiweError("Keycloak subject is required to bind a wallet")
    configured = configured_chain_id()
    if chain_id is not None and chain_id != configured:
        raise SiweError("Wallet must use configured Base chain")
    chain_id = configured
    addr = checksum_address(address)
    issued = (now or datetime.now(UTC)).replace(microsecond=0)
    issued_at = issued.isoformat().replace("+00:00", "Z")
    nonce = secrets.token_hex(16)
    message = build_siwe_message(
        address=addr,
        nonce=nonce,
        issued_at=issued_at,
        chain_id=chain_id,
    )
    challenge = SiweNonce(
        nonce=nonce,
        issued_at=issued_at,
        domain=SIWE_DOMAIN,
        uri=SIWE_URI,
        statement=SIWE_STATEMENT,
        version=SIWE_VERSION,
        chain_id=chain_id,
        message=message,
    )

    _nonces[user.sub] = (challenge, time.time() + _NONCE_TTL_SECONDS)
    return challenge


def consume_nonce(keycloak_sub: str) -> SiweNonce:
    row = _nonces.pop(keycloak_sub, None)
    if row is None:
        raise SiweError("SIWE nonce is missing; request a new nonce")
    nonce, exp = row
    if time.time() > exp:
        raise SiweError("SIWE nonce expired; request a new nonce")
    return nonce


@asynccontextmanager
async def wallet_verifier():
    """Construct from operator configuration; never use proof-supplied RPC URLs."""
    rpc_url = os.environ.get("AUTH_SIWE_BASE_RPC_URL", "")
    address = os.environ.get("AUTH_SIWE_6492_VALIDATOR_ADDRESS", "")
    code_hash = os.environ.get("AUTH_SIWE_6492_VALIDATOR_CODE_HASH", "")
    async with httpx.AsyncClient() as client:
        try:
            validator = None
            if address or code_hash:
                validator = CounterfactualValidator(
                    address, bytes.fromhex(code_hash.removeprefix("0x"))
                )
            verifier = BaseWalletVerifier(
                chain_id=configured_chain_id(),
                rpc_url=rpc_url,
                client=client,
                counterfactual_validator=validator,
            )
        except ValueError as exc:
            raise SiweError("Base wallet verifier configuration is invalid") from exc
        yield verifier


async def bind_wallet(
    session: AsyncSession,
    user: AuthMeResponse,
    *,
    message: str,
    signature: str,
) -> WalletBinding:
    if not user.sub or not str(user.sub).strip():
        raise SiweError("Keycloak subject is required to bind a wallet")
    challenge = consume_nonce(user.sub)
    if message != challenge.message:
        raise SiweError("SIWE message must match the server-issued challenge")
    async with wallet_verifier() as verifier:
        parsed = await verify_siwe_bind(
            message=message,
            signature=signature,
            expected_nonce=challenge.nonce,
            verifier=verifier,
            expected_chain_id=configured_chain_id(),
            expected_domain=challenge.domain,
            expected_uri=challenge.uri,
        )
    # Drop the signature immediately. Do not assign it onto the row.
    del signature
    return await upsert_wallet_binding(
        session,
        keycloak_sub=user.sub,
        email=user.email,
        wallet_address=parsed.address,
    )


async def upsert_wallet_binding(
    session: AsyncSession,
    *,
    keycloak_sub: str,
    email: str | None,
    wallet_address: str,
) -> WalletBinding:
    addr = checksum_address(wallet_address)
    taken = await session.execute(
        select(UserWalletBinding).where(UserWalletBinding.wallet_address == addr)
    )
    existing_addr = taken.scalar_one_or_none()
    if existing_addr is not None and existing_addr.keycloak_sub != keycloak_sub:
        raise SiweError("wallet is already bound to another person")

    found = await session.execute(
        select(UserWalletBinding).where(UserWalletBinding.keycloak_sub == keycloak_sub)
    )
    row = found.scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None:
        row = UserWalletBinding(
            id=uuid.uuid4(),
            keycloak_sub=keycloak_sub,
            email=email,
            wallet_address=addr,
            bound_at=now,
        )
        session.add(row)
    else:
        row.wallet_address = addr
        row.email = email
        row.bound_at = now
    await session.flush()
    await session.refresh(row)
    return WalletBinding(
        keycloak_sub=row.keycloak_sub,
        email=row.email,
        wallet_address=row.wallet_address,
        bound_at=row.bound_at,
    )


async def get_wallet_binding(
    session: AsyncSession, keycloak_sub: str
) -> WalletBinding | None:
    found = await session.execute(
        select(UserWalletBinding).where(UserWalletBinding.keycloak_sub == keycloak_sub)
    )
    row = found.scalar_one_or_none()
    if row is None:
        return None
    return WalletBinding(
        keycloak_sub=row.keycloak_sub,
        email=row.email,
        wallet_address=row.wallet_address,
        bound_at=row.bound_at,
    )
