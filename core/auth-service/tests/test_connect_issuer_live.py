"""Real Keycloak MFA/AMR regression in a disposable, loopback-only container."""

import base64
import hashlib
import hmac
import importlib.util
import json
import secrets
import sys
import time
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import docker
import httpx
import jwt
import pytest
from auth_service.connect_session import verified_issuer_facts
from controlplane_api.config import settings

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "infra/keycloak"))
SPEC = importlib.util.spec_from_file_location(
    "connect_issuer", ROOT / "infra/keycloak/connect_issuer.py"
)
issuer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(issuer)
from configure_idp_brokers import AdminClient, _json_request, admin_token


class Form(HTMLParser):
    action = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "form" and fields.get("id") in {"kc-form-login", "kc-otp-login-form"}:
            self.action = unescape(fields["action"])


def otp(seed):
    counter = int(time.time()) // 30
    digest = hmac.new(
        base64.b32decode(seed), counter.to_bytes(8, "big"), hashlib.sha1
    ).digest()
    offset = digest[-1] & 15
    return str(
        (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF) % 1000000
    ).zfill(6)


@pytest.fixture(scope="module")
def server():
    client = docker.from_env()
    password = secrets.token_urlsafe(32)
    container = client.containers.run(
        "quay.io/keycloak/keycloak:26.5",
        "start-dev",
        environment={
            "KC_BOOTSTRAP_ADMIN_USERNAME": "connect-test-admin",
            "KC_BOOTSTRAP_ADMIN_PASSWORD": password,
        },
        ports={"8080/tcp": ("127.0.0.1", None)},
        detach=True,
    )
    try:
        container.reload()
        port = container.attrs["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
        base = "http://127.0.0.1:" + port
        # Quarkus augmentation can exceed 90s on the shared two-CPU runner.
        # Keep a bounded cold-start allowance without slowing healthy starts or
        # skipping the real MFA assertions. Never print bootstrap credentials.
        started = time.monotonic()
        deadline = started + 180
        with httpx.Client(trust_env=False, timeout=2) as c:
            while True:
                container.reload()
                state = container.attrs["State"]
                if state.get("Status") != "running":
                    pytest.fail(
                        "Disposable Keycloak exited before readiness "
                        f"(status={state.get('Status')}, exit={state.get('ExitCode')}, "
                        f"oom={state.get('OOMKilled')})",
                        pytrace=False,
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    pytest.fail(
                        "Disposable Keycloak startup exceeded 180s "
                        f"(status={state.get('Status')}, oom={state.get('OOMKilled')})",
                        pytrace=False,
                    )
                try:
                    if (
                        c.get(
                            base + "/realms/master", timeout=min(2, remaining)
                        ).status_code
                        == 200
                    ):
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(min(1, max(0, deadline - time.monotonic())))
        yield base, password
    finally:
        container.remove(force=True, v=True)
        client.close()


@pytest.fixture
def configured(server, monkeypatch):
    base, password = server
    monkeypatch.setattr(settings, "keycloak_issuer", base + "/realms/controlplane")
    token = admin_token(base, "connect-test-admin", password)
    admin = AdminClient(base, token)
    realm = json.loads(
        (ROOT / "infra/keycloak/import/controlplane-realm.json").read_text()
    )
    # No personal/dev identities or external IdPs enter this disposable test.
    realm["users"] = []
    realm["identityProviders"] = []
    frontend = next(c for c in realm["clients"] if c["clientId"] == issuer.FRONTEND)
    frontend["redirectUris"] = ["http://localhost:3000/callback"]
    realm["clients"] = [frontend]
    try:
        _json_request("DELETE", base + "/admin/realms/controlplane", token=token)
    except Exception as exc:
        if "404" not in str(exc):
            raise
    _json_request("POST", base + "/admin/realms", token=token, payload=realm)
    before = issuer.executions(admin, admin.get("")["browserFlow"])
    secret = secrets.token_urlsafe(40)
    issuer.configure(admin, secret)
    issuer.configure(admin, secret)
    assert issuer.executions(admin, admin.get("")["browserFlow"]) == before
    seed = base64.b32encode(secrets.token_bytes(20)).decode()
    for username, enabled_otp in [("with-otp", True), ("password-only", False)]:
        credentials = [
            {
                "type": "password",
                "value": "disposable-password-strong",
                "temporary": False,
            }
        ]
        if enabled_otp:
            credentials.append(
                {
                    "type": "otp",
                    "userLabel": "disposable OTP",
                    "secretData": json.dumps({"value": seed}),
                    "credentialData": json.dumps(
                        {
                            "subType": "totp",
                            "digits": 6,
                            "counter": 0,
                            "period": 30,
                            "algorithm": "HmacSHA1",
                            "secretEncoding": "BASE32",
                        }
                    ),
                }
            )
        admin.post(
            "/users",
            {
                "username": username,
                "enabled": True,
                "emailVerified": True,
                "email": username + "@example.com",
                "firstName": "Synthetic",
                "lastName": "Test",
                "credentials": credentials,
            },
        )
    return base, admin, secret, seed


def login(configured, username, acr, *, bad_otp=False, delay_at=None):
    base, _, secret, seed = configured
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    with httpx.Client(trust_env=False, follow_redirects=False) as c:
        response = c.get(
            base + "/realms/controlplane/protocol/openid-connect/auth",
            params={
                "client_id": issuer.FRONTEND,
                "redirect_uri": "http://localhost:3000/callback",
                "response_type": "code",
                "scope": "openid profile email",
                "state": secrets.token_hex(16),
                "nonce": secrets.token_hex(16),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "prompt": "login",
                "max_age": "0",
                "acr_values": acr,
            },
        )
        form = Form()
        form.feed(response.text)
        assert form.action
        for cookie in c.cookies.jar:
            cookie.secure = False
        response = c.post(
            form.action,
            data={"username": username, "password": "disposable-password-strong"},
        )
        challenged = 'id="otp"' in response.text
        if challenged:
            if delay_at == "otp":
                time.sleep(1.1)  # Cross a Keycloak epoch-second boundary.
            form = Form()
            form.feed(response.text)
            assert form.action
            assert urlparse(form.action).netloc == urlparse(base).netloc
            for cookie in c.cookies.jar:
                cookie.secure = False
            response = c.post(
                form.action,
                data={"otp": "000000" if bad_otp else otp(seed), "login": "Sign In"},
            )
        if bad_otp:
            assert response.status_code == 200 and 'id="otp"' in response.text
            return None, None, challenged
        assert response.status_code == 302, response.status_code
        location = urljoin(base, response.headers["location"])
        assert location.startswith("http://localhost:3000/callback?")
        code = parse_qs(urlparse(location).query)["code"][0]
        if delay_at == "exchange":
            time.sleep(1.1)  # The callback can take longer than one second.
        response = c.post(
            base + "/realms/controlplane/protocol/openid-connect/token",
            data={
                "grant_type": "authorization_code",
                "client_id": issuer.FRONTEND,
                "redirect_uri": "http://localhost:3000/callback",
                "code": code,
                "code_verifier": verifier,
            },
        )
        response.raise_for_status()
        access = response.json()["access_token"]
        jwks = c.get(base + "/realms/controlplane/protocol/openid-connect/certs").json()
        key = next(
            k
            for k in jwks["keys"]
            if k["kid"] == jwt.get_unverified_header(access)["kid"]
        )
        claims = jwt.decode(
            access,
            jwt.PyJWK.from_dict(key).key,
            algorithms=["RS256"],
            issuer=base + "/realms/controlplane",
            options={"verify_aud": False},
        )
        response = c.post(
            base + "/realms/controlplane/protocol/openid-connect/token/introspect",
            data={"client_id": issuer.CLIENT, "client_secret": secret, "token": access},
        )
        response.raise_for_status()
        return claims, response.json(), challenged


@pytest.mark.parametrize("acr", ["1", "2"])
def test_real_password_and_otp_claims_and_introspection(configured, acr):
    claims, active, challenged = login(configured, "with-otp", acr)
    assert challenged, "Existing OTP must not be bypassed by a lower requested ACR"
    assert claims["acr"] == "2" and set(claims["amr"]) == {"pwd", "otp"}
    facts = verified_issuer_facts(claims, active)
    assert facts["second_factor_at"] is not None


@pytest.mark.parametrize("delay_at", ["otp", "exchange"])
def test_real_mfa_references_survive_browser_delays(configured, delay_at):
    claims, active, challenged = login(configured, "with-otp", "2", delay_at=delay_at)
    assert challenged
    assert claims["acr"] == "2" and set(claims["amr"]) == {"pwd", "otp"}
    assert verified_issuer_facts(claims, active)["second_factor_at"] is not None
    _base, admin, _, _ = configured
    for execution in issuer.executions(admin, issuer.FLOW):
        if execution.get("providerId") in {
            "auth-username-password-form",
            "auth-otp-form",
        }:
            config = admin.get(
                "/authentication/config/" + execution["authenticationConfig"]
            )["config"]
            assert config["default.reference.maxAge"] == "300"


def test_password_only_cannot_supply_verified_second_factor(configured):
    claims, active, challenged = login(configured, "password-only", "1")
    assert not challenged and "otp" not in claims["amr"]
    assert claims["acr"] != "2"
    assert verified_issuer_facts(claims, active)["second_factor_at"] is None


def test_wrong_otp_never_issues_token(configured):
    _, _, challenged = login(configured, "with-otp", "2", bad_otp=True)
    assert challenged


def test_existing_introspection_secret_is_never_rotated(configured):
    _, admin, secret, _ = configured
    with pytest.raises(issuer.ConnectIssuerError, match="differs"):
        issuer.configure(admin, secrets.token_urlsafe(40))
    assert (
        admin.get(
            "/clients/" + issuer.client(admin, issuer.CLIENT)["id"] + "/client-secret"
        )["value"]
        == secret
    )


def test_disabled_source_otp_is_not_silently_repaired(configured):
    _, admin, secret, _ = configured
    source = admin.get("")["browserFlow"]
    rows = issuer.executions(admin, source)
    otp = next(e for e in rows if e.get("providerId") == "auth-otp-form")
    admin.put(
        "/authentication/flows/" + source + "/executions",
        {**otp, "requirement": "DISABLED"},
    )
    with pytest.raises(issuer.ConnectIssuerError, match="disabled"):
        issuer.configure(admin, secret)
    assert (
        next(e for e in issuer.executions(admin, source) if e["id"] == otp["id"])[
            "requirement"
        ]
        == "DISABLED"
    )
