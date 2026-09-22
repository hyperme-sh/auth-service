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
    mapping = {"microsoft": {}, "google": {}, "github": {}}
    personal = idp.classify_idp_account(
        "microsoft",
        {"tid": idp.MSA_TENANT_ID},
        mapping,
    )
    gmail = idp.classify_idp_account("google", {}, mapping)
    user = idp.classify_idp_account("github", {"login": "octocat"}, mapping)
    assert personal.account == "individual"
    assert personal.enterprise is None
    assert gmail.account == "individual"
    assert user.account == "individual"


def test_mapped_org_becomes_that_enterprise() -> None:
    mapping = {
        "microsoft": {"11111111-1111-1111-1111-111111111111": "Fyber Labs"},
        "google": {"fyberlabs.com": "Fyber Labs"},
        "github": {"FyberLabs": "Fyber Labs"},
    }
    entra = idp.classify_idp_account(
        "microsoft",
        {"tid": "11111111-1111-1111-1111-111111111111"},
        mapping,
    )
    workspace = idp.classify_idp_account(
        "google",
        {"hd": "fyberlabs.com"},
        mapping,
    )
    org = idp.classify_idp_account(
        "github",
        {"orgs": ["FyberLabs"]},
        mapping,
    )
    assert (entra.account, entra.enterprise) == ("organization", "Fyber Labs")
    assert (workspace.account, workspace.org) == ("organization", "fyberlabs.com")
    assert org.enterprise == "Fyber Labs"


def test_unmapped_org_stays_an_organization_without_an_enterprise() -> None:
    other = idp.classify_idp_account(
        "microsoft",
        {"tid": "22222222-2222-2222-2222-222222222222"},
        {"microsoft": {}, "google": {}, "github": {}},
    )
    assert other.account == "organization"
    assert other.enterprise is None


def test_unset_map_is_distinct_from_an_empty_map() -> None:
    assert idp.parse_enterprise_map(None) is None
    assert idp.parse_enterprise_map("  ") is None
    assert idp.parse_enterprise_map("{}") == {
        "microsoft": {},
        "google": {},
        "github": {},
    }


def test_map_rejects_unknown_providers_and_bad_keys() -> None:
    with pytest.raises(idp.IdpMapError):
        idp.parse_enterprise_map('{"okta": {}}')
    with pytest.raises(idp.IdpMapError):
        idp.parse_enterprise_map('{"microsoft": {"bad key": "Fyber Labs"}}')


def test_common_tenant_accepts_personal_and_work_accounts() -> None:
    endpoints = idp.microsoft_endpoints(None)
    assert endpoints["authorizationUrl"] == (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    )
    assert endpoints["issuer"].endswith("/common/v2.0")
    with pytest.raises(idp.IdpMapError):
        idp.microsoft_endpoints("https://evil.example")


def test_enterprise_mapper_names_the_org_not_a_secret() -> None:
    specs = idp.enterprise_mappers(
        {
            "microsoft": {"11111111-1111-1111-1111-111111111111": "Fyber Labs"},
            "google": {},
            "github": {},
        }
    )
    assert len(specs) == 1
    assert specs[0]["identityProviderAlias"] == "microsoft"
    assert "Fyber Labs" in specs[0]["config"]["attributes"]
    assert "clientSecret" not in json.dumps(specs)


def test_realm_import_copies_org_claims_and_token_attributes() -> None:
    realm = json.loads(REALM_PATH.read_text(encoding="utf-8"))
    names = {item["name"] for item in realm["identityProviderMappers"]}
    assert {
        "microsoft-tenant",
        "fyber-individual-microsoft",
        "google-hosted-domain",
        "github-login",
    } <= names
    frontend = next(
        client
        for client in realm["clients"]
        if client["clientId"] == "controlplane-frontend"
    )
    claim_names = {item["name"] for item in frontend["protocolMappers"]}
    assert {"idp_org", "idp_login", "idp_account", "enterprise"} <= claim_names
