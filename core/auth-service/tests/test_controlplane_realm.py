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


def test_import_keeps_self_registration_closed() -> None:
    realm = _realm()
    assert realm["registrationAllowed"] is False
    assert '"directAccessGrantsEnabled": true' not in REALM_PATH.read_text(encoding="utf-8")


def test_test_plane_registration_does_not_touch_the_password_grant() -> None:
    import importlib.util

    path = REPO_ROOT / "infra" / "keycloak" / "test_registration.py"
    spec = importlib.util.spec_from_file_location("test_registration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    updated = module.apply_test_registration(
        {"registrationAllowed": False, "smtpServer": {}}
    )
    assert updated["registrationAllowed"] is True
    assert updated["registrationEmailAsUsername"] is True
    assert updated["verifyEmail"] is False
    assert "directAccessGrantsEnabled" not in updated
    assert updated["smtpServer"] == {}


def test_existing_clients_and_bootstrap_user_remain() -> None:
    realm = _realm()
    client_ids = {c["clientId"] for c in realm["clients"]}
    assert client_ids == {
        "controlplane-frontend",
        "controlplane-mobile",
        "controlplane-device",
        "controlplane-m2m",
        "controlplane-api-key",
        "hypermesh-native",
    }
    users = {u["username"] for u in realm["users"]}
    assert "chris@fyberlabs.com" in users
    frontend = next(c for c in realm["clients"] if c["clientId"] == "controlplane-frontend")
    assert frontend["publicClient"] is True
    assert frontend["directAccessGrantsEnabled"] is False
    assert frontend["attributes"]["pkce.code.challenge.method"] == "S256"


def test_imported_user_has_configure_totp() -> None:
    realm = _realm()
    chris = next(u for u in realm["users"] if u["username"] == "chris@fyberlabs.com")
    assert "CONFIGURE_TOTP" in chris["requiredActions"]
    assert "UPDATE_PASSWORD" in chris["requiredActions"]
    assert "webauthn-register" not in chris["requiredActions"]
    assert "webauthn-register-passwordless" not in chris["requiredActions"]
    actions = {a["alias"]: a for a in realm["requiredActions"]}
    assert actions["CONFIGURE_TOTP"]["defaultAction"] is False
    assert actions["UPDATE_PASSWORD"]["defaultAction"] is False
    assert actions["webauthn-register"]["defaultAction"] is False
    assert not chris.get("credentials")
    raw = REALM_PATH.read_text(encoding="utf-8")
    assert "Test@123!" not in raw
    for cred in chris.get("credentials") or []:
        assert not cred.get("value")


def _users_by_username() -> dict:
    return {u["username"]: u for u in _realm()["users"]}


def test_pan_test_identities_are_split_and_have_no_secrets() -> None:
    realm = _realm()
    roles = {r["name"] for r in realm["roles"]["realm"]}
    groups = {g["name"] for g in realm["groups"]}
    assert roles == {"renter", "host", "admin"}
    assert groups == {"renter", "host"}
    assert "leaser" not in roles
    assert "leaser" not in groups

    users = _users_by_username()
    assert set(users) == {
        "chris@fyberlabs.com",
        "renter",
        "leaser",
        "admin",
    }

    renter = users["renter"]
    assert renter["email"] == "renter@test.hyperme.sh"
    assert renter["groups"] == ["/renter"]
    assert renter["realmRoles"] == ["renter"]
    assert renter.get("requiredActions") == []

    leaser = users["leaser"]
    assert leaser["email"] == "leaser@test.hyperme.sh"
    assert leaser["groups"] == ["/host"]
    assert leaser["realmRoles"] == ["host"]
    assert "renter" not in leaser["realmRoles"]
    assert leaser.get("requiredActions") == []

    admin = users["admin"]
    assert admin["email"] == "admin@test.hyperme.sh"
    assert admin.get("groups") in ([], None)
    assert admin["realmRoles"] == ["admin"]
    assert "renter" not in admin["realmRoles"]
    assert "host" not in admin["realmRoles"]
    assert admin.get("requiredActions") == []

    raw = REALM_PATH.read_text(encoding="utf-8")
    for user in (renter, leaser, admin):
        assert not user.get("credentials")
        assert "UPDATE_PASSWORD" not in (user.get("requiredActions") or [])
        assert "CONFIGURE_TOTP" not in (user.get("requiredActions") or [])
    assert "PANOPTICON_TEST_" not in raw
    assert "panopticon-test-renter-password" not in raw


def test_frontend_groups_claim_mapper_stays_on_public_pkce_client() -> None:
    frontend = next(
        c for c in _realm()["clients"] if c["clientId"] == "controlplane-frontend"
    )
    mappers = frontend["protocolMappers"]
    groups = next(m for m in mappers if m["protocolMapper"] == "oidc-group-membership-mapper")
    assert groups["config"]["claim.name"] == "groups"
    assert groups["config"]["access.token.claim"] == "true"
    assert frontend["publicClient"] is True
    assert frontend["directAccessGrantsEnabled"] is False


def test_frontend_client_includes_portal_test_redirects() -> None:
    """portal.test uses the existing public client. Import is first-start only."""
    clients = [
        c for c in _realm()["clients"] if c["clientId"] == "controlplane-frontend"
    ]
    assert len(clients) == 1
    frontend = clients[0]
    redirects = frontend["redirectUris"]
    origins = frontend["webOrigins"]
    assert "http://localhost:3000/*" in redirects
    assert "http://127.0.0.1:3000/*" in redirects
    assert "https://portal.test.hyperme.sh/*" in redirects
    assert "https://portal.test.hyperme.sh/api/auth/callback" in redirects
    assert "https://portal.test.hyperme.sh/api/auth/callback/keycloak" in redirects
    assert "http://localhost:3000" in origins
    assert "http://127.0.0.1:3000" in origins
    assert "https://portal.test.hyperme.sh" in origins
    assert not any(
        c.get("clientId") == "controlplane-portal" for c in _realm()["clients"]
    )


def _native_module():
    import importlib.util

    path = REPO_ROOT / "infra" / "keycloak" / "hypermesh_native.py"
    spec = importlib.util.spec_from_file_location("hypermesh_native", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hypermesh_native_client_contract() -> None:
    """Visor/CLI public client: PKCE S256, device grant, no offline_access."""
    module = _native_module()
    client = module.declared_client(_realm())
    module.validate_declared_client(client)
    assert client["publicClient"] is True
    assert "secret" not in client
    assert client["standardFlowEnabled"] is True
    assert client["directAccessGrantsEnabled"] is False
    assert client["implicitFlowEnabled"] is False
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert client["attributes"]["oauth2.device.authorization.grant.enabled"] == "true"
    assert "access.token.lifespan" not in client["attributes"]
    assert client["redirectUris"] == ["http://127.0.0.1/callback"]
    assert client["webOrigins"] == []
    assert "offline_access" not in client["defaultClientScopes"]
    assert "offline_access" not in client["optionalClientScopes"]
    assert _realm()["accessTokenLifespan"] == 300


class _FakeKeycloak:
    """In-memory admin API. A new client starts with realm-default scopes."""

    def __init__(self) -> None:
        self.clients: list[dict] = []
        self.posts: list[str] = []
        self.client_puts = 0
        self.scope_puts: list[str] = []
        self.scope_deletes: list[str] = []
        self.catalog = [
            {"id": name, "name": name}
            for name in (
                "web-origins",
                "acr",
                "profile",
                "roles",
                "email",
                "basic",
                "address",
                "phone",
                "microprofile-jwt",
            )
        ]
        self.catalog.append({"id": "offline", "name": "offline_access"})
        self.assigned: dict[str, dict[str, list[dict[str, str]]]] = {}

    def get(self, path: str):
        if path.startswith("/clients?clientId="):
            client_id = path.split("=", 1)[1]
            return [item for item in self.clients if item.get("clientId") == client_id]
        if path == "/client-scopes":
            return self.catalog
        if "/default-client-scopes" in path and path.count("/") == 3:
            return self.assigned[path.split("/")[2]]["default"]
        if "/optional-client-scopes" in path and path.count("/") == 3:
            return self.assigned[path.split("/")[2]]["optional"]
        raise AssertionError(path)

    def post(self, path: str, payload: dict) -> None:
        assert path == "/clients"
        if any(item.get("clientId") == payload.get("clientId") for item in self.clients):
            raise AssertionError("duplicate client")
        client = dict(payload)
        client["id"] = "native-1"
        self.clients.append(client)
        self.posts.append(path)
        self.assigned["native-1"] = {
            "default": [
                {"id": "profile", "name": "profile"},
                {"id": "email", "name": "email"},
                {"id": "roles", "name": "roles"},
                {"id": "web-origins", "name": "web-origins"},
                {"id": "acr", "name": "acr"},
            ],
            "optional": [
                {"id": "address", "name": "address"},
                {"id": "phone", "name": "phone"},
                {"id": "microprofile-jwt", "name": "microprofile-jwt"},
                {"id": "offline", "name": "offline_access"},
            ],
        }

    def put(self, path: str, payload) -> None:
        if path == "/clients/native-1":
            self.client_puts += 1
            updated = dict(payload)
            updated["id"] = "native-1"
            self.clients = [updated]
            return
        parts = path.strip("/").split("/")
        assert parts[0] == "clients" and parts[1] == "native-1"
        bucket = "default" if parts[2].startswith("default") else "optional"
        scope_id = parts[3]
        name = next(item["name"] for item in self.catalog if item["id"] == scope_id)
        self.assigned["native-1"][bucket].append({"id": scope_id, "name": name})
        self.scope_puts.append(path)

    def delete(self, path: str) -> None:
        parts = path.strip("/").split("/")
        bucket = "default" if parts[2].startswith("default") else "optional"
        scope_id = parts[3]
        self.assigned["native-1"][bucket] = [
            item for item in self.assigned["native-1"][bucket] if item["id"] != scope_id
        ]
        self.scope_deletes.append(path)


def test_hypermesh_native_upsert_is_idempotent() -> None:
    module = _native_module()
    admin = _FakeKeycloak()
    module.ensure_hypermesh_native(admin)
    module.ensure_hypermesh_native(admin)

    assert admin.posts == ["/clients"]
    assert len(admin.clients) == 1
    client = admin.clients[0]
    assert client["id"] == "native-1"
    assert client["publicClient"] is True
    assert "secret" not in client
    assert client["redirectUris"] == ["http://127.0.0.1/callback"]
    assert client["webOrigins"] == []
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert client["attributes"]["oauth2.device.authorization.grant.enabled"] == "true"
    assert "access.token.lifespan" not in client["attributes"]
    assert admin.client_puts == 1

    stale = module.upsert_payload(
        module.declared_client(),
        {"id": "native-1", "attributes": {"access.token.lifespan": "86400", "keep": "yes"}},
    )
    assert stale["id"] == "native-1"
    assert stale["attributes"]["access.token.lifespan"] == ""
    assert stale["attributes"]["keep"] == "yes"
    assert "secret" not in stale
    assert admin.scope_deletes == ["/clients/native-1/optional-client-scopes/offline"]
    assert admin.scope_puts == ["/clients/native-1/default-client-scopes/basic"]

    default_names = {item["name"] for item in admin.assigned["native-1"]["default"]}
    optional_names = {item["name"] for item in admin.assigned["native-1"]["optional"]}
    assert "offline_access" not in default_names
    assert "offline_access" not in optional_names
    assert "basic" in default_names
