"""SIWE uses the payment rail chain without accepting contradictory overrides."""

import pytest
from auth_service.siwe import SiweError, configured_chain_id


@pytest.mark.parametrize("chain", [8453, 84532])
def test_siwe_reads_canonical_usdc_chain(monkeypatch, chain):
    monkeypatch.setenv("USDC_CHAIN_ID", str(chain))
    monkeypatch.delenv("AUTH_SIWE_CHAIN_ID", raising=False)
    assert configured_chain_id() == chain
    monkeypatch.setenv("AUTH_SIWE_CHAIN_ID", str(chain))
    assert configured_chain_id() == chain
    monkeypatch.setenv("AUTH_SIWE_CHAIN_ID", str(84532 if chain == 8453 else 8453))
    with pytest.raises(SiweError, match="match USDC"):
        configured_chain_id()
