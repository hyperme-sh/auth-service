"""Sanity checks for the controlplane Keycloak realm import (no Keycloak process)."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
REALM_PATH = REPO_ROOT / "infra" / "keycloak" / "import" / "controlplane-realm.json"

PLACEHOLDER_MARKERS = (
    "unset-microsoft-client-id",
    "unset-microsoft-client-secret",
    "unset-github-client-id",
    "unset-github-client-secret",
    "unset-google-client-id",
    "unset-google-client-secret",
    "KC_IDP_MICROSOFT_CLIENT_ID",
    "KC_IDP_GITHUB_CLIENT_ID",
    "KC_IDP_GOOGLE_CLIENT_ID",
)


def _realm() -> dict:
    return json.loads(REALM_PATH.read_text(encoding="utf-8"))


def test_realm_declares_entra_github_google_brokers() -> None:
    providers = {p["alias"]: p for p in _realm()["identityProviders"]}
    assert set(providers) == {"microsoft", "github", "google"}
    assert providers["microsoft"]["displayName"] == "Microsoft Entra"
    assert providers["microsoft"]["providerId"] == "oidc"
    assert providers["github"]["providerId"] == "github"
    assert providers["google"]["providerId"] == "google"
    for alias in ("microsoft", "github", "google"):
        assert providers[alias]["enabled"] is True
        assert providers[alias]["hideOnLogin"] is False


def test_idp_secrets_are_env_placeholders_not_live_values() -> None:
    raw = REALM_PATH.read_text(encoding="utf-8")
    for marker in PLACEHOLDER_MARKERS:
        assert marker in raw
    for provider in _realm()["identityProviders"]:
        client_id = provider["config"]["clientId"]
        client_secret = provider["config"]["clientSecret"]
        assert client_id.startswith("${KC_IDP_")
        assert client_secret.startswith("${KC_IDP_")
        assert "unset-" in client_id
        assert "unset-" in client_secret


def test_mfa_is_optional_but_configured() -> None:
    realm = _realm()
    assert realm["otpPolicyType"] == "totp"
    assert "ES256" in realm["webAuthnPolicySignatureAlgorithms"]
    actions = {a["alias"]: a for a in realm["requiredActions"]}
    for alias in (
        "CONFIGURE_TOTP",
        "webauthn-register",
        "webauthn-register-passwordless",
    ):
        assert actions[alias]["enabled"] is True
        assert actions[alias]["defaultAction"] is False


def test_existing_clients_and_password_user_remain() -> None:
    realm = _realm()
    client_ids = {c["clientId"] for c in realm["clients"]}
    assert client_ids == {
        "controlplane-frontend",
        "controlplane-mobile",
        "controlplane-device",
        "controlplane-m2m",
        "controlplane-api-key",
    }
    users = {u["username"] for u in realm["users"]}
    assert "chris@fyberlabs.com" in users
