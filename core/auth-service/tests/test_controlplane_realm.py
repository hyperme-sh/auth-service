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
    assert client["attributes"]["client.session.idle.timeout"] == "1800"
    assert client["attributes"]["client.session.max.lifespan"] == "36000"
    assert client["attributes"]["oauth2.device.code.lifespan"] == "600"
    assert "access.token.lifespan" not in client["attributes"]
    assert "client.offline.session.idle.timeout" not in client["attributes"]
    assert "client.offline.session.max.lifespan" not in client["attributes"]
    assert client["redirectUris"] == ["http://127.0.0.1/callback"]
    assert client["webOrigins"] == []
    assert client["defaultClientScopes"] == ["basic", "roles", "email", "profile", "acr"]
    assert client["optionalClientScopes"] == []
    assert "offline_access" not in client["defaultClientScopes"]
    assert "web-origins" not in client["defaultClientScopes"]
    realm = _realm()
    frontend = next(item for item in realm["clients"] if item["clientId"] == "controlplane-frontend")
    frontend_groups = next(item for item in frontend["protocolMappers"] if item["name"] == "groups")
    assert client["protocolMappers"][0] == frontend_groups
    assert client["protocolMappers"][1:] == module.token_claim_mappers()
    assert client["protocolMappers"] == module.declared_protocol_mappers(realm)
    assert _realm()["accessTokenLifespan"] == 300


class _FakeKeycloak:
    """In-memory admin API. A new client starts with realm-default scopes."""

    def __init__(self) -> None:
        self.clients: list[dict] = []
        self.posts: list[str] = []
        self.client_puts = 0
        self.scope_puts: list[str] = []
        self.scope_deletes: list[str] = []
        self.mapper_posts: list[str] = []
        self.mapper_puts: list[str] = []
        self.mapper_deletes: list[str] = []
        self._mapper_seq = 0
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
        self.catalog.append({"id": "extra", "name": "extra-scope"})
        self.assigned: dict[str, dict[str, list[dict[str, str]]]] = {}
        self.mappers: dict[str, list[dict]] = {}

    def get(self, path: str):
        if path.startswith("/clients?clientId="):
            client_id = path.split("=", 1)[1]
            return [item for item in self.clients if item.get("clientId") == client_id]
        if path == "/client-scopes":
            return self.catalog
        if path.endswith("/protocol-mappers/models"):
            return list(self.mappers.get(path.split("/")[2], []))
        if "/default-client-scopes" in path and path.count("/") == 3:
            return self.assigned[path.split("/")[2]]["default"]
        if "/optional-client-scopes" in path and path.count("/") == 3:
            return self.assigned[path.split("/")[2]]["optional"]
        raise AssertionError(path)

    def post(self, path: str, payload: dict) -> None:
        if path.endswith("/protocol-mappers/models"):
            client_uuid = path.split("/")[2]
            self._mapper_seq += 1
            item = dict(payload)
            item["id"] = f"mapper-{self._mapper_seq}"
            self.mappers.setdefault(client_uuid, []).append(item)
            self.mapper_posts.append(path)
            return
        assert path == "/clients"
        if any(item.get("clientId") == payload.get("clientId") for item in self.clients):
            raise AssertionError("duplicate client")
        client = dict(payload)
        client["id"] = "native-1"
        self.clients.append(client)
        self.posts.append(path)
        self.mappers["native-1"] = []
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
        parts = path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "clients":
            client_uuid = parts[1]
            updated = dict(payload)
            updated["id"] = client_uuid
            for index, client in enumerate(self.clients):
                if client.get("id") == client_uuid:
                    self.clients[index] = updated
                    self.client_puts += 1
                    return
            raise AssertionError(path)
        if "/protocol-mappers/models/" in path:
            client_uuid = parts[1]
            mapper_id = parts[4]
            updated = dict(payload)
            updated["id"] = mapper_id
            for index, item in enumerate(self.mappers.get(client_uuid, [])):
                if item.get("id") == mapper_id:
                    self.mappers[client_uuid][index] = updated
                    self.mapper_puts.append(path)
                    return
            raise AssertionError(path)
        client_uuid = parts[1]
        bucket = "default" if parts[2].startswith("default") else "optional"
        scope_id = parts[3]
        name = next(item["name"] for item in self.catalog if item["id"] == scope_id)
        self.assigned[client_uuid][bucket].append({"id": scope_id, "name": name})
        self.scope_puts.append(path)

    def delete(self, path: str) -> None:
        parts = path.strip("/").split("/")
        client_uuid = parts[1]
        if "/protocol-mappers/models/" in path:
            mapper_id = parts[4]
            self.mappers[client_uuid] = [
                item for item in self.mappers.get(client_uuid, []) if item.get("id") != mapper_id
            ]
            self.mapper_deletes.append(path)
            return
        bucket = "default" if parts[2].startswith("default") else "optional"
        scope_id = parts[3]
        self.assigned[client_uuid][bucket] = [
            item for item in self.assigned[client_uuid][bucket] if item["id"] != scope_id
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
    assert client["attributes"]["client.session.idle.timeout"] == "1800"
    assert client["attributes"]["client.session.max.lifespan"] == "36000"
    assert client["attributes"]["oauth2.device.code.lifespan"] == "600"
    assert client["attributes"]["access.token.lifespan"] is None
    assert client["attributes"]["client.offline.session.idle.timeout"] is None
    assert client["attributes"]["client.offline.session.max.lifespan"] is None
    assert admin.client_puts == 1
    assert admin.scope_puts == ["/clients/native-1/default-client-scopes/basic"]
    assert set(admin.scope_deletes) == {
        "/clients/native-1/default-client-scopes/web-origins",
        "/clients/native-1/optional-client-scopes/address",
        "/clients/native-1/optional-client-scopes/phone",
        "/clients/native-1/optional-client-scopes/microprofile-jwt",
        "/clients/native-1/optional-client-scopes/offline",
    }
    assert len(admin.mapper_posts) == 6
    assert admin.mapper_deletes == []

    default_names = {item["name"] for item in admin.assigned["native-1"]["default"]}
    optional_names = {item["name"] for item in admin.assigned["native-1"]["optional"]}
    assert default_names == {"basic", "roles", "email", "profile", "acr"}
    assert optional_names == set()
    assert {item["name"] for item in admin.mappers["native-1"]} == {
        item["name"] for item in module.declared_protocol_mappers()
    }
    assert "groups" in {item["name"] for item in admin.mappers["native-1"]}


def test_hypermesh_native_corrects_drift_and_keeps_other_clients() -> None:
    module = _native_module()
    admin = _FakeKeycloak()
    year = str(365 * 24 * 60 * 60)
    other = {
        "id": "frontend-1",
        "clientId": "controlplane-frontend",
        "secret": "leave-me",
        "redirectUris": ["https://portal.test.hyperme.sh/*"],
        "webOrigins": ["https://portal.test.hyperme.sh"],
    }
    admin.clients = [
        {
            "id": "native-1",
            "clientId": "hypermesh-native",
            "publicClient": False,
            "secret": "hand-set-secret",
            "standardFlowEnabled": True,
            "implicitFlowEnabled": True,
            "directAccessGrantsEnabled": True,
            "redirectUris": [
                "http://127.0.0.1/callback",
                "http://127.0.0.1:3000/callback",
            ],
            "webOrigins": ["*"],
            "attributes": {
                "pkce.code.challenge.method": "plain",
                "client.session.idle.timeout": year,
                "client.session.max.lifespan": year,
                "client.offline.session.max.lifespan": year,
                "oauth2.device.code.lifespan": "999999",
                "hand.edit": "yes",
            },
        },
        other,
    ]
    admin.assigned["native-1"] = {
        "default": [
            {"id": "basic", "name": "basic"},
            {"id": "roles", "name": "roles"},
            {"id": "email", "name": "email"},
            {"id": "profile", "name": "profile"},
            {"id": "acr", "name": "acr"},
            {"id": "web-origins", "name": "web-origins"},
            {"id": "extra", "name": "extra-scope"},
        ],
        "optional": [
            {"id": "phone", "name": "phone"},
            {"id": "offline", "name": "offline_access"},
        ],
    }
    admin.mappers["native-1"] = [
        {
            "id": "stray-1",
            "name": "stray-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "consentRequired": False,
            "config": {"claim.name": "stray"},
        },
        {
            "id": "idp-org-1",
            "name": "idp_org",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "consentRequired": False,
            "config": {"claim.name": "nope"},
        },
    ]

    module.ensure_hypermesh_native(admin)

    assert other in admin.clients
    assert other["secret"] == "leave-me"
    assert other["redirectUris"] == ["https://portal.test.hyperme.sh/*"]
    assert admin.posts == []
    native = next(item for item in admin.clients if item["clientId"] == "hypermesh-native")
    assert native["id"] == "native-1"
    assert native["publicClient"] is True
    assert native["directAccessGrantsEnabled"] is False
    assert native["implicitFlowEnabled"] is False
    assert "secret" not in native
    assert native["redirectUris"] == ["http://127.0.0.1/callback"]
    assert native["webOrigins"] == []
    assert native["attributes"]["pkce.code.challenge.method"] == "S256"
    assert native["attributes"]["client.session.idle.timeout"] == "1800"
    assert native["attributes"]["client.session.max.lifespan"] == "36000"
    assert native["attributes"]["oauth2.device.code.lifespan"] == "600"
    assert native["attributes"]["client.offline.session.max.lifespan"] is None
    assert native["attributes"]["client.offline.session.idle.timeout"] is None
    assert native["attributes"]["hand.edit"] is None
    assert native["attributes"]["access.token.lifespan"] is None
    assert year not in json.dumps(native["attributes"])
    default_names = {item["name"] for item in admin.assigned["native-1"]["default"]}
    optional_names = {item["name"] for item in admin.assigned["native-1"]["optional"]}
    assert default_names == {"basic", "roles", "email", "profile", "acr"}
    assert optional_names == set()
    assert "stray-mapper" not in {item["name"] for item in admin.mappers["native-1"]}
    declared = {
        item["name"]: item for item in module.declared_protocol_mappers()
    }
    live = {item["name"]: item for item in admin.mappers["native-1"]}
    assert set(live) == set(declared)
    assert live["groups"]["protocolMapper"] == "oidc-group-membership-mapper"
    assert live["groups"]["config"]["claim.name"] == "groups"
    assert live["idp_org"]["config"]["claim.name"] == "idp_org"


def test_native_client_failure_is_reported_apart_from_brokers(capsys, monkeypatch) -> None:
    import importlib.util

    path = REPO_ROOT / "infra" / "keycloak" / "configure_idp_brokers.py"
    spec = importlib.util.spec_from_file_location("configure_idp_brokers", path)
    assert spec is not None and spec.loader is not None
    brokers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(brokers)
    calls: list[str] = []

    def boom(_admin: object) -> None:
        calls.append("native")
        raise brokers.NativeClientError("session cap rejected")

    def brokers_ok(_admin: object) -> None:
        calls.append("brokers")

    monkeypatch.setattr(brokers, "ensure_hypermesh_native", boom)
    monkeypatch.setattr(brokers, "configure", brokers_ok)
    assert brokers.apply_realm_updates(object()) == 1
    assert calls == ["native", "brokers"]
    error = capsys.readouterr().err
    assert "hypermesh-native client was not applied: session cap rejected" in error
    assert "IdP broker configure failed" not in error

    calls.clear()

    def native_ok(_admin: object) -> None:
        calls.append("native")

    def brokers_bad(_admin: object) -> None:
        calls.append("brokers")
        raise brokers.ConfigureError("token claim missing")

    monkeypatch.setattr(brokers, "ensure_hypermesh_native", native_ok)
    monkeypatch.setattr(brokers, "configure", brokers_bad)
    assert brokers.apply_realm_updates(object()) == 1
    assert calls == ["native", "brokers"]
    error = capsys.readouterr().err
    assert "IdP broker configure failed: token claim missing" in error
    assert "hypermesh-native client was not applied" not in error

    calls.clear()

    def network(_admin: object) -> None:
        calls.append("native")
        raise brokers.urllib.error.URLError("connection refused")

    monkeypatch.setattr(brokers, "ensure_hypermesh_native", network)
    monkeypatch.setattr(brokers, "configure", brokers_ok)
    assert brokers.apply_realm_updates(object()) == 1
    assert calls == ["native", "brokers"]
    error = capsys.readouterr().err
    assert "hypermesh-native client was not applied" in error
    assert "connection refused" in error
    assert "IdP broker configure failed" not in error
