"""Broker account classification. No Keycloak process and no live secrets."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "infra" / "keycloak" / "idp_enterprise.py"
REALM_PATH = REPO_ROOT / "infra" / "keycloak" / "import" / "controlplane-realm.json"


def _load():
    spec = importlib.util.spec_from_file_location("idp_enterprise", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


idp = _load()


def test_personal_microsoft_and_gmail_stay_individual() -> None:
    personal = idp.classify_idp_account("microsoft", {"tid": idp.MSA_TENANT_ID})
    gmail = idp.classify_idp_account("google", {})
    user = idp.classify_idp_account("github", {"login": "octocat"})
    assert personal.account == "individual"
    assert personal.org is None
    assert gmail.account == "individual"
    assert user.account == "individual"


def test_org_account_keeps_the_idp_key_without_a_legal_name() -> None:
    entra = idp.classify_idp_account(
        "microsoft",
        {"tid": "11111111-1111-1111-1111-111111111111"},
    )
    workspace = idp.classify_idp_account("google", {"hd": "fyberlabs.com"})
    org = idp.classify_idp_account("github", {"orgs": ["FyberLabs"]})
    assert (entra.account, entra.org) == (
        "organization",
        "11111111-1111-1111-1111-111111111111",
    )
    assert (workspace.account, workspace.org) == ("organization", "fyberlabs.com")
    assert (org.account, org.org) == ("organization", "FyberLabs")


def test_common_tenant_accepts_personal_and_work_accounts() -> None:
    endpoints = idp.microsoft_endpoints(None)
    assert endpoints["authorizationUrl"] == (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    )
    assert endpoints["issuer"].endswith("/common/v2.0")
    with pytest.raises(idp.IdpMapError):
        idp.microsoft_endpoints("https://evil.example")


def test_claim_mappers_do_not_carry_a_secret_or_an_enterprise_name() -> None:
    specs = idp.claim_copy_mappers()
    blob = json.dumps(specs)
    assert "clientSecret" not in blob
    assert "enterprise" not in blob
    assert any(item["name"] == "microsoft-directory-roles" for item in specs)


def test_realm_import_copies_org_claims_and_token_attributes() -> None:
    realm = json.loads(REALM_PATH.read_text(encoding="utf-8"))
    names = {item["name"] for item in realm["identityProviderMappers"]}
    assert {
        "microsoft-provider",
        "microsoft-tenant",
        "microsoft-directory-roles",
        "fyber-individual-microsoft",
        "google-provider",
        "google-hosted-domain",
        "github-provider",
        "github-login",
    } <= names
    frontend = next(
        client
        for client in realm["clients"]
        if client["clientId"] == "controlplane-frontend"
    )
    claim_names = {item["name"] for item in frontend["protocolMappers"]}
    assert {"idp_provider", "idp_org", "idp_login", "idp_account", "idp_wids"} <= claim_names
    assert "enterprise" not in claim_names


def test_entra_identity_is_session_bound_in_import_and_reconciliation():
    broker = next(m for m in idp.claim_copy_mappers() if m['name'] == 'microsoft-session-identity')
    assert broker['identityProviderMapper'] == 'oidc-user-session-note-idp-mapper'
    assert {item['key'] for item in json.loads(broker['config']['claims'])} == {'tid','oid'}
    assert broker in json.loads(REALM_PATH.read_text())['identityProviderMappers']
    mappings = {m['name']:m for m in idp.token_claim_mappers()}
    for name, note in [('login_provider','identity_provider'), ('entra_tenant_id','tid'), ('entra_object_id','oid')]:
        assert mappings[name]['protocolMapper'] == 'oidc-usersessionmodel-note-mapper'
        assert mappings[name]['config']['user.session.note'] == note
