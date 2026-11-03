"""Opt-in real Keycloak test. Uses only a disposable loopback realm/container."""

import base64
import hashlib
import json
import os
import sys
import uuid
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "infra/keycloak"))
import account_types as accounts
from configure_idp_brokers import AdminClient, _json_request, admin_token

BASE = os.environ.get("KEYCLOAK_CLASSIFICATION_TEST_URL", "")
pytestmark = pytest.mark.skipif(not BASE, reason="requires a disposable local Keycloak container")


class LoginForm(HTMLParser):
    action = None
    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "form" and fields.get("id") == "kc-form-login":
            self.action = fields["action"]


def login(username):
    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    with httpx.Client(follow_redirects=True) as browser:
        response = browser.get(BASE + "/realms/controlplane/protocol/openid-connect/auth", params={
            "client_id": "controlplane-frontend", "redirect_uri": "http://localhost:3000/callback",
            "response_type": "code", "scope": "openid", "state": "test", "nonce": str(uuid.uuid4()),
            "code_challenge": challenge, "code_challenge_method": "S256",
        })
        # Docker's bridge peer makes Keycloak mark cookies Secure. This isolated
        # loopback HTTP harness exercises authentication, not TLS transport.
        for cookie in browser.cookies.jar:
            cookie.secure = False
        parser = LoginForm(); parser.feed(response.text)
        assert parser.action, response.status_code
        assert urlparse(parser.action).netloc == urlparse(BASE).netloc
        response = browser.post(parser.action, data={"username": username, "password": "isolated-test-password"}, follow_redirects=False)
        assert response.status_code == 302
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        token = browser.post(BASE + "/realms/controlplane/protocol/openid-connect/token", data={
            "grant_type": "authorization_code", "client_id": "controlplane-frontend",
            "redirect_uri": "http://localhost:3000/callback", "code": code, "code_verifier": verifier,
        })
        token.raise_for_status()
        access = token.json()["access_token"]
        claims = json.loads(base64.urlsafe_b64decode(access.split(".")[1] + "=="))
        return access, claims


def test_real_pkce_claims_and_self_service_cannot_forge_human_identity():
    assert urlparse(BASE).hostname in {"127.0.0.1", "localhost"}
    password = os.environ["KEYCLOAK_CLASSIFICATION_TEST_ADMIN_PASSWORD"]
    token = admin_token(BASE, "classification-test-admin", password)
    # The test owns the whole container and replaces only its disposable realm.
    admin = AdminClient(BASE, token)
    realm = json.loads((ROOT / "infra/keycloak/import/controlplane-realm.json").read_text())
    _json_request("DELETE", BASE + "/admin/realms/controlplane", token=token)
    _json_request("POST", BASE + "/admin/realms", token=token, payload=realm)
    accounts.configure(admin)
    accounts.configure(admin)
    users = {}
    for kind in ["human", "service", "unclassified"]:
        username = "classification-" + kind
        admin.post("/users", {"username": username, "enabled": True, "emailVerified": True,
            "email": username + "@example.com", "firstName": "Test", "lastName": "Identity",
            "credentials": [{"type": "password", "value": "isolated-test-password", "temporary": False}]})
        user = admin.get("/users?username=" + username + "&exact=true")[0]
        users[kind] = user
        if kind != "unclassified":
            accounts.classify(admin, user["id"], kind)
        access, claims = login(username)
        assert claims.get("account_type") == (None if kind == "unclassified" else kind)
        assert "pwd" in claims["amr"]
        # Try forging an administrator-only attribute through the account API.
        if kind in {"service", "unclassified"}:
            response = httpx.post(BASE + "/realms/controlplane/account", headers={"Authorization": "Bearer " + access},
                json={"username": username, "firstName": "Test", "lastName": "Identity", "email": username + "@example.com",
                      "attributes": {"account_type": ["human"]}})
            assert response.status_code in {204, 400, 403}
            saved = admin.get("/users/" + user["id"])
            assert (saved.get("attributes") or {}).get("account_type") != ["human"]
            assert login(username)[1].get("account_type") != "human"
    client = admin.get("/clients?clientId=controlplane-m2m")[0]
    secret = admin.get("/clients/" + client["id"] + "/client-secret")["value"]
    response = httpx.post(BASE + "/realms/controlplane/protocol/openid-connect/token", data={
        "grant_type": "client_credentials", "client_id": "controlplane-m2m", "client_secret": secret})
    response.raise_for_status()
    claims = json.loads(base64.urlsafe_b64decode(response.json()["access_token"].split(".")[1] + "=="))
    assert claims["account_type"] == "service"
