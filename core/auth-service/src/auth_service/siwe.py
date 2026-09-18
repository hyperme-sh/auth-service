"""EIP-4361 SIWE verify for wallet bind. Not a login.

Recovers the signer address from a personal_sign of the SIWE message.
Does not persist the signature or any private key.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import is_hex_address, to_checksum_address

SIWE_DOMAIN = os.environ.get("AUTH_SIWE_DOMAIN", "localhost")
SIWE_URI = os.environ.get("AUTH_SIWE_URI", "http://localhost:3000")
SIWE_STATEMENT = (
    "Bind this wallet to the identified Panopticon person. This is not a login."
)
SIWE_VERSION = "1"
DEFAULT_CHAIN_ID = 1

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
    fields = {m.group(1): m.group(2).strip() for m in _FIELD.finditer(text)}
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
    if sig.startswith("0x"):
        sig = sig[2:]
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


def verify_siwe_bind(
    *,
    message: str,
    signature: str,
    expected_nonce: str,
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
    if parsed.version != SIWE_VERSION:
        raise SiweError("SIWE version must be 1")
    recovered = recover_siwe_address(parsed.raw, signature)
    if recovered.lower() != parsed.address.lower():
        raise SiweError("SIWE recovered address does not match the message")
    return parsed
