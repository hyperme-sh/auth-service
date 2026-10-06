"""EIP-4361 SIWE verify for wallet bind. Not a login.

Recovers the signer address from a personal_sign of the SIWE message.
Does not persist the signature or any private key.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from controlplane_identity.wallet import BaseWalletVerifier, WalletProofError
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import is_hex_address, to_checksum_address

SIWE_DOMAIN = os.environ.get("AUTH_SIWE_DOMAIN", "localhost")
SIWE_URI = os.environ.get("AUTH_SIWE_URI", "http://localhost:3000")
SIWE_STATEMENT = (
    "Bind this wallet to the identified Panopticon person. This is not a login."
)
SIWE_VERSION = "1"
DEFAULT_CHAIN_ID = 84532


def configured_chain_id() -> int:
    default = "8453" if os.environ.get("FASTAPI_ENV") == "production" else "84532"
    try:
        chain = int(os.environ.get("AUTH_SIWE_CHAIN_ID", default))
    except ValueError as exc:
        raise SiweError("Invalid Base chain configuration") from exc
    if chain not in {8453, 84532}:
        raise SiweError("Configure Base 8453 or 84532")
    return chain


_HEADER = re.compile(
    r"^(?P<domain>\S+) wants you to sign in with your Ethereum account:\n"
    r"(?P<address>0x[a-fA-F0-9]{40})\n\n",
    re.MULTILINE,
)
_FIELD = re.compile(r"^(URI|Version|Chain ID|Nonce|Issued At): (.+)$", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class SiweMessage:
    domain: str
    address: str
    statement: str | None
    uri: str
    version: str
    chain_id: int
    nonce: str
    issued_at: str
    raw: str


class SiweError(ValueError):
    """SIWE message or signature is not acceptable."""


def checksum_address(value: str) -> str:
    if not is_hex_address(value):
        raise SiweError("wallet address is not a hex address")
    return to_checksum_address(value)


def build_siwe_message(
    *,
    address: str,
    nonce: str,
    issued_at: str,
    domain: str = SIWE_DOMAIN,
    uri: str = SIWE_URI,
    statement: str = SIWE_STATEMENT,
    version: str = SIWE_VERSION,
    chain_id: int = DEFAULT_CHAIN_ID,
) -> str:
    addr = checksum_address(address)
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{addr}\n"
        f"\n"
        f"{statement}\n"
        f"\n"
        f"URI: {uri}\n"
        f"Version: {version}\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}"
    )


def parse_siwe_message(raw: str) -> SiweMessage:
    text = str(raw or "").replace("\r\n", "\n").strip()
    if not text:
        raise SiweError("SIWE message is empty")
    header = _HEADER.match(text)
    if header is None:
        raise SiweError("SIWE message is not EIP-4361")
    matches = list(_FIELD.finditer(text))
    fields = {m.group(1): m.group(2).strip() for m in matches}
    if len(fields) != len(matches):
        raise SiweError("SIWE fields must be unique")
    required = ("URI", "Version", "Chain ID", "Nonce", "Issued At")
    missing = [name for name in required if name not in fields]
    if missing:
        raise SiweError("SIWE message is missing required fields")
    try:
        chain_id = int(fields["Chain ID"])
    except ValueError as e:
        raise SiweError("SIWE chain id is not an integer") from e
    body = text[header.end() :]
    statement = None
    if "\nURI:" in f"\n{body}":
        statement = body.split("\nURI:", 1)[0].strip() or None
    return SiweMessage(
        domain=header.group("domain"),
        address=checksum_address(header.group("address")),
        statement=statement,
        uri=fields["URI"],
        version=fields["Version"],
        chain_id=chain_id,
        nonce=fields["Nonce"],
        issued_at=fields["Issued At"],
        raw=text,
    )


def recover_siwe_address(message: str, signature: str) -> str:
    """Recover the signer. Caller must drop the signature after this returns."""
    if not signature or not str(signature).strip():
        raise SiweError("SIWE signature is required")
    sig = str(signature).strip()
    sig = sig.removeprefix("0x")
    if len(sig) != 130 or any(c not in "0123456789abcdefABCDEF" for c in sig):
        raise SiweError("SIWE signature is not a hex signature")
    try:
        recovered = Account.recover_message(
            encode_defunct(text=message),
            signature=bytes.fromhex(sig),
        )
    except Exception as e:
        raise SiweError("SIWE signature does not recover an address") from e
    return checksum_address(recovered)


async def verify_siwe_bind(
    *,
    message: str,
    signature: str,
    expected_nonce: str,
    verifier: BaseWalletVerifier,
    expected_chain_id: int,
    expected_domain: str = SIWE_DOMAIN,
    expected_uri: str = SIWE_URI,
) -> SiweMessage:
    parsed = parse_siwe_message(message)
    if parsed.nonce != expected_nonce:
        raise SiweError("SIWE nonce does not match the identified session")
    if parsed.domain != expected_domain:
        raise SiweError("SIWE domain does not match")
    if parsed.uri != expected_uri:
        raise SiweError("SIWE uri does not match")
    if parsed.version != SIWE_VERSION or parsed.statement != SIWE_STATEMENT:
        raise SiweError("SIWE version or purpose does not match")
    if expected_chain_id not in {8453, 84532} or parsed.chain_id != expected_chain_id:
        raise SiweError("SIWE chain must match configured Base chain")
    try:
        issued = datetime.fromisoformat(parsed.issued_at)
        age = (datetime.now(UTC) - issued).total_seconds()
        if not -30 <= age <= 600:
            raise ValueError("expired or future challenge")
    except (ValueError, TypeError) as exc:
        raise SiweError("SIWE issued time is invalid or expired") from exc
    sig = signature.removeprefix("0x")
    if (
        not sig
        or len(sig) > 32768
        or len(sig) % 2
        or any(c not in "0123456789abcdefABCDEF" for c in sig)
    ):
        raise SiweError("SIWE signature is not bounded hex data")
    try:
        verified = await verifier.verify_personal_signature(
            address=parsed.address,
            message=message,
            signature=bytes.fromhex(sig),
            chain_id=parsed.chain_id,
        )
    except WalletProofError as exc:
        raise SiweError("SIWE wallet proof could not be verified on Base") from exc
    if verified != parsed.address:
        raise SiweError("SIWE verified address does not match the message")
    return parsed
