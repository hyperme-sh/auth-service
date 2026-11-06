"""Bind one recovered SIWE address onto the identified Keycloak person."""

from __future__ import annotations

import os
import secrets
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

import httpx
from controlplane_identity.wallet import BaseWalletVerifier, CounterfactualValidator
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
from auth_service.siwe_nonces import SiweNonceStore, SiweStoreUnavailable


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


async def issue_siwe_nonce(
    user: AuthMeResponse,
    *,
    address: str,
    store: SiweNonceStore,
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

    await store.put(user.sub, asdict(challenge))
    return challenge


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
    store: SiweNonceStore,
) -> WalletBinding:
    if not user.sub or not str(user.sub).strip():
        raise SiweError("Keycloak subject is required to bind a wallet")
    try:
        challenge = SiweNonce(**await store.consume(user.sub))
    except TypeError as exc:
        raise SiweStoreUnavailable("SIWE nonce storage returned invalid data") from exc
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


async def upsert_wallet_binding(session, *, keycloak_sub, email, wallet_address):
    from auth_service.identity_owner import call
    from pydantic import TypeAdapter
    result = await call('bind-wallet', subject=keycloak_sub,email=email,wallet_address=wallet_address)
    return TypeAdapter(WalletBinding).validate_python(result)


async def get_wallet_binding(session, keycloak_sub):
    from auth_service.identity_owner import call
    from pydantic import TypeAdapter
    result = await call('get-wallet', subject=keycloak_sub)
    return None if result is None else TypeAdapter(WalletBinding).validate_python(result)
