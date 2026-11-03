"""SIWE bindings consume exact, expiring, subject-owned Base challenges."""

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import httpx
import pytest
from auth_service import wallet_bind
from auth_service.schemas import AuthMeResponse, SiweNonceRequest
from auth_service.siwe import SiweError, configured_chain_id, verify_siwe_bind
from controlplane_identity.wallet import BaseWalletVerifier
from eth_account import Account
from eth_account.messages import encode_defunct

ACCOUNT = Account.from_key(bytes.fromhex("33" * 32))
PERSON = AuthMeResponse(sub="base-bind-person", email="base@example.test")


def sign(message):
    return ACCOUNT.sign_message(encode_defunct(text=message)).signature.hex()


@pytest.mark.parametrize("chain", [232, 1, 8453])
async def test_nonce_refuses_wrong_chain(chain, monkeypatch, nonce_store):
    monkeypatch.setenv("AUTH_SIWE_CHAIN_ID", "84532")
    with pytest.raises(SiweError, match="Base chain"):
        await wallet_bind.issue_siwe_nonce(
            PERSON, store=nonce_store, address=ACCOUNT.address, chain_id=chain
        )


async def test_nonce_default_uses_server_chain(monkeypatch, nonce_store):
    monkeypatch.setenv("AUTH_SIWE_CHAIN_ID", "8453")
    assert SiweNonceRequest(address=ACCOUNT.address).chain_id is None
    challenge = await wallet_bind.issue_siwe_nonce(
        PERSON, store=nonce_store, address=ACCOUNT.address
    )
    assert challenge.chain_id == 8453 and challenge.nonce.isalnum()


@pytest.mark.asyncio
async def test_bind_consumes_nonce_and_persists_verified_address(
    base_wallet_verifier, monkeypatch, nonce_store
):
    challenge = await wallet_bind.issue_siwe_nonce(
        PERSON, store=nonce_store, address=ACCOUNT.address
    )
    persist = AsyncMock(return_value="bound")
    monkeypatch.setattr(wallet_bind, "upsert_wallet_binding", persist)
    assert (
        await wallet_bind.bind_wallet(
            None,
            PERSON,
            store=nonce_store,
            message=challenge.message,
            signature=sign(challenge.message),
        )
        == "bound"
    )
    assert persist.call_args.kwargs == {
        "keycloak_sub": PERSON.sub,
        "email": PERSON.email,
        "wallet_address": ACCOUNT.address,
    }
    with pytest.raises(SiweError, match="missing"):
        await wallet_bind.bind_wallet(
            None,
            PERSON,
            store=nonce_store,
            message=challenge.message,
            signature=sign(challenge.message),
        )
    assert persist.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["address", "chain", "statement", "duplicate", "whitespace"]
)
async def test_modified_challenge_never_persists(
    change, base_wallet_verifier, monkeypatch, nonce_store
):
    challenge = await wallet_bind.issue_siwe_nonce(
        PERSON, store=nonce_store, address=ACCOUNT.address
    )
    altered = {
        "address": challenge.message.replace(ACCOUNT.address, Account.create().address),
        "chain": challenge.message.replace("Chain ID: 84532", "Chain ID: 232"),
        "statement": challenge.message.replace(
            "Bind this wallet", "Authorize a payout"
        ),
        "duplicate": challenge.message + "\nChain ID: 232",
        "whitespace": challenge.message + "\n",
    }[change]
    persist = AsyncMock()
    monkeypatch.setattr(wallet_bind, "upsert_wallet_binding", persist)
    with pytest.raises(SiweError, match="server-issued"):
        await wallet_bind.bind_wallet(
            None, PERSON, store=nonce_store, message=altered, signature=sign(altered)
        )
    persist.assert_not_awaited()


@pytest.mark.asyncio
async def test_subject_and_expiry_checks(
    base_wallet_verifier, monkeypatch, nonce_store
):
    challenge = await wallet_bind.issue_siwe_nonce(
        PERSON, store=nonce_store, address=ACCOUNT.address
    )
    with pytest.raises(SiweError, match="missing"):
        await wallet_bind.bind_wallet(
            None,
            AuthMeResponse(sub="other-person"),
            store=nonce_store,
            message=challenge.message,
            signature=sign(challenge.message),
        )
    await nonce_store.redis.expire(nonce_store.key(PERSON.sub), 0)
    with pytest.raises(SiweError, match="expired"):
        await wallet_bind.bind_wallet(
            None,
            PERSON,
            store=nonce_store,
            message=challenge.message,
            signature=sign(challenge.message),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "altered",
    [
        "Chain ID: 232",
        "Issued At: 2000-01-01T00:00:00Z",
        "Issued At: 2999-01-01T00:00:00Z",
        "Issued At: malformed",
    ],
)
async def test_direct_siwe_verification_rejects_invalid_context(
    altered, base_wallet_verifier, nonce_store
):
    challenge = await wallet_bind.issue_siwe_nonce(
        PERSON, store=nonce_store, address=ACCOUNT.address
    )
    prefix = altered.split(":", 1)[0] + ":"
    message = "\n".join(
        altered if line.startswith(prefix) else line
        for line in challenge.message.splitlines()
    )
    with pytest.raises(SiweError):
        await verify_siwe_bind(
            message=message,
            signature=sign(message),
            expected_nonce=challenge.nonce,
            expected_chain_id=84532,
            verifier=base_wallet_verifier,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("valid", [True, False])
async def test_contract_wallet_binds_only_after_base_1271_acceptance(
    valid, monkeypatch, nonce_store
):
    monkeypatch.setenv("AUTH_SIWE_CHAIN_ID", "84532")
    calls = []

    def respond(request):
        body = json.loads(request.content)
        calls.append(body)
        results = {
            "eth_chainId": "0x14a34",
            "eth_blockNumber": "0x123",
            "eth_getCode": "0x6000",
            "eth_call": "0x" + ("1626ba7e" + "00" * 28 if valid else "00" * 32),
        }
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "result": results[body["method"]]}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        verifier = BaseWalletVerifier(
            chain_id=84532, rpc_url="https://base.test", client=client
        )

        @asynccontextmanager
        async def factory():
            yield verifier

        monkeypatch.setattr(wallet_bind, "wallet_verifier", factory)
        persist = AsyncMock(return_value="bound")
        monkeypatch.setattr(wallet_bind, "upsert_wallet_binding", persist)
        challenge = await wallet_bind.issue_siwe_nonce(
            PERSON, store=nonce_store, address=ACCOUNT.address
        )
        if valid:
            assert (
                await wallet_bind.bind_wallet(
                    None,
                    PERSON,
                    store=nonce_store,
                    message=challenge.message,
                    signature="0xaabb",
                )
                == "bound"
            )
            assert persist.call_args.kwargs["wallet_address"] == ACCOUNT.address
        else:
            with pytest.raises(SiweError):
                await wallet_bind.bind_wallet(
                    None,
                    PERSON,
                    store=nonce_store,
                    message=challenge.message,
                    signature="0xaabb",
                )
            persist.assert_not_awaited()
        assert calls[-1]["params"][0]["to"] == ACCOUNT.address
        assert calls[-1]["params"][1] == "0x123"


@pytest.mark.asyncio
async def test_missing_rpc_configuration_fails_binding_closed(monkeypatch):
    monkeypatch.setenv("AUTH_SIWE_CHAIN_ID", "84532")
    monkeypatch.delenv("AUTH_SIWE_BASE_RPC_URL", raising=False)
    with pytest.raises(SiweError, match="configuration"):
        async with wallet_bind.wallet_verifier():
            pytest.fail("Missing RPC must not create a verifier")


def test_chain_defaults_and_invalid_configuration(monkeypatch):
    monkeypatch.delenv("AUTH_SIWE_CHAIN_ID", raising=False)
    monkeypatch.setenv("FASTAPI_ENV", "production")
    assert configured_chain_id() == 8453
    monkeypatch.setenv("FASTAPI_ENV", "test")
    assert configured_chain_id() == 84532
    monkeypatch.setenv("AUTH_SIWE_CHAIN_ID", "232")
    with pytest.raises(SiweError):
        configured_chain_id()


@pytest.mark.asyncio
async def test_failed_proof_also_consumes_nonce(
    base_wallet_verifier, monkeypatch, nonce_store
):
    challenge = await wallet_bind.issue_siwe_nonce(
        PERSON, store=nonce_store, address=ACCOUNT.address
    )
    persist = AsyncMock()
    monkeypatch.setattr(wallet_bind, "upsert_wallet_binding", persist)
    wrong = (
        Account.create()
        .sign_message(encode_defunct(text=challenge.message))
        .signature.hex()
    )
    with pytest.raises(SiweError):
        await wallet_bind.bind_wallet(
            None, PERSON, store=nonce_store, message=challenge.message, signature=wrong
        )
    with pytest.raises(SiweError, match="missing"):
        await wallet_bind.bind_wallet(
            None,
            PERSON,
            store=nonce_store,
            message=challenge.message,
            signature=sign(challenge.message),
        )
    persist.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["domain", "uri", "nonce", "duplicate"])
async def test_siwe_context_fields_rejected(field, base_wallet_verifier, nonce_store):
    challenge = await wallet_bind.issue_siwe_nonce(
        PERSON, store=nonce_store, address=ACCOUNT.address
    )
    changed = {
        "domain": challenge.message.replace(challenge.domain, "attacker.example", 1),
        "uri": challenge.message.replace(
            "URI: " + challenge.uri, "URI: https://attacker.example"
        ),
        "nonce": challenge.message.replace(challenge.nonce, "anothernonce"),
        "duplicate": challenge.message + "\nNonce: anothernonce",
    }[field]
    with pytest.raises(SiweError):
        await verify_siwe_bind(
            message=changed,
            signature=sign(changed),
            expected_nonce=challenge.nonce,
            expected_chain_id=84532,
            verifier=base_wallet_verifier,
        )
