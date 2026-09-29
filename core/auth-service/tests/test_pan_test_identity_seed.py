"""Unit tests for the pan-test Keycloak identity seed (no Keycloak process)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from api.domain.operator.population import (
    SEEDED_TEST_ADMIN_EMAIL,
    SEEDED_TEST_ADMIN_OPERATOR_CLAIMS,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SEED_PATH = REPO_ROOT / "infra" / "keycloak" / "seed_pan_test_identities.py"


def _load_seed():
    spec = importlib.util.spec_from_file_location("seed_pan_test_identities", SEED_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


seed = _load_seed()


def test_catalog_is_three_split_users_with_existing_grant_names() -> None:
    seed.catalog_invariants()
    by_user = {ident.username: ident for ident in seed.IDENTITIES}
    assert set(by_user) == {
        "renter",
        "leaser",
        "admin",
    }

    renter = by_user["renter"]
    assert renter.email == "renter@test.hyperme.sh"
    assert renter.groups == ("renter",)
    assert renter.realm_roles == ("renter",)
    assert renter.kv_secret == "panopticon-test-renter-password"
    assert renter.password_env == "PANOPTICON_TEST_RENTER_PASSWORD"

    leaser = by_user["leaser"]
    assert leaser.email == "leaser@test.hyperme.sh"
    assert leaser.groups == ("host",)
    assert leaser.realm_roles == ("host",)
    assert "leaser" not in leaser.groups
    assert "leaser" not in leaser.realm_roles
    assert leaser.kv_secret == "panopticon-test-leaser-password"

    admin = by_user["admin"]
    assert admin.email == "admin@test.hyperme.sh"
    assert admin.groups == ()
    assert admin.realm_roles == ("admin",)
    assert admin.email == SEEDED_TEST_ADMIN_EMAIL
    assert admin.operator_claims == SEEDED_TEST_ADMIN_OPERATOR_CLAIMS
    assert "org:own" not in admin.operator_claims
    assert "org:manage" not in admin.operator_claims
    assert renter.operator_claims == ()
    assert leaser.operator_claims == ()
    assert "renter" not in admin.realm_roles
    assert "host" not in admin.realm_roles
    assert admin.kv_secret == "panopticon-test-portal-admin-password"
    assert admin.kv_secret != seed.BOOTSTRAP_KV_PASSWORD
    assert admin.kv_secret != seed.API_ADMIN_KV_PASSWORD


def test_require_passwords_fails_closed_on_empty_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PANOPTICON_TEST_RENTER_PASSWORD", raising=False)
    monkeypatch.setenv("PANOPTICON_TEST_LEASER_PASSWORD", "unused")
    monkeypatch.setenv("PANOPTICON_TEST_PORTAL_ADMIN_PASSWORD", "unused")
    with pytest.raises(seed.SeedError, match="PANOPTICON_TEST_RENTER_PASSWORD"):
        seed.require_passwords()


def test_require_passwords_fails_closed_on_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PANOPTICON_TEST_RENTER_PASSWORD", "  ")
    monkeypatch.setenv("PANOPTICON_TEST_LEASER_PASSWORD", "unused")
    monkeypatch.setenv("PANOPTICON_TEST_PORTAL_ADMIN_PASSWORD", "unused")
    with pytest.raises(seed.SeedError, match="PANOPTICON_TEST_RENTER_PASSWORD"):
        seed.require_passwords()


class _FakeAdmin:
    def __init__(self) -> None:
        self.roles = {}
        self.groups = {}
        self.users = {}
        self.user_roles: dict[str, set[str]] = {}
        self.user_groups: dict[str, set[str]] = {}
        self.group_roles: dict[str, set[str]] = {}
        self.passwords_set: list[str] = []
        self.mapper_created = False
        self.posts: list[tuple[str, object]] = []

    def get(self, path: str):
        if path.startswith("/roles/"):
            name = path.split("/roles/", 1)[1]
            if name in self.roles:
                return self.roles[name]
            raise seed.SeedError(f"GET {path} failed: HTTP 404")
        if path.startswith("/groups/") and "/role-mappings/realm" in path:
            gid = path.split("/")[2]
            return [{"name": n} for n in self.group_roles.get(gid, set())]
        if path.startswith("/groups?") or path == "/groups?briefRepresentation=false":
            return list(self.groups.values())
        if path.startswith("/users?") and "username=" in path:
            username = path.split("username=", 1)[1].split("&", 1)[0]
            username = username.replace("%40", "@")
            return [u for u in self.users.values() if u["username"] == username]
        if path.startswith("/users?") and "email=" in path:
            email = path.split("email=", 1)[1].split("&", 1)[0]
            email = email.replace("%40", "@")
            return [u for u in self.users.values() if u["email"] == email]
        if path.startswith("/users/") and path.endswith("/role-mappings/realm"):
            uid = path.split("/")[2]
            return [{"name": n} for n in self.user_roles.get(uid, set())]
        if path.startswith("/users/") and path.endswith("/groups"):
            uid = path.split("/")[2]
            names = self.user_groups.get(uid, set())
            return [
                {"id": self.groups[name]["id"], "name": name}
                for name in names
                if name in self.groups
            ]
        if path.startswith("/clients?clientId="):
            return [
                {
                    "id": "frontend-id",
                    "publicClient": True,
                    "directAccessGrantsEnabled": False,
                }
            ]
        if path == "/clients/frontend-id/protocol-mappers/models":
            return []
        raise AssertionError(f"unexpected GET {path}")

    def post(self, path: str, payload):
        self.posts.append((path, payload))
        if path == "/roles":
            name = payload["name"]
            self.roles[name] = {"name": name, "id": f"role-{name}"}
            return None
        if path == "/groups":
            name = payload["name"]
            self.groups[name] = {"id": f"group-{name}", "name": name, "path": f"/{name}"}
            return None
        if path == "/users":
            uid = f"user-{payload['username']}"
            self.users[uid] = {**payload, "id": uid}
            self.user_roles[uid] = set()
            self.user_groups[uid] = set()
            return None
        if path.endswith("/role-mappings/realm"):
            if path.startswith("/groups/"):
                gid = path.split("/")[2]
                self.group_roles.setdefault(gid, set()).update(
                    item["name"] for item in payload
                )
                return None
            uid = path.split("/")[2]
            self.user_roles.setdefault(uid, set()).update(item["name"] for item in payload)
            return None
        if path == "/clients/frontend-id/protocol-mappers/models":
            self.mapper_created = True
            return None
        raise AssertionError(f"unexpected POST {path}")

    def put(self, path: str, payload):
        if path.endswith("/reset-password"):
            uid = path.split("/")[2]
            self.passwords_set.append(uid)
            return None
        if "/users/" in path and path.endswith("/groups/" + path.rsplit("/", 1)[-1]):
            uid = path.split("/")[2]
            gid = path.rsplit("/", 1)[-1]
            name = next(n for n, g in self.groups.items() if g["id"] == gid)
            self.user_groups.setdefault(uid, set()).add(name)
            return None
        if path.startswith("/users/"):
            uid = path.split("/")[2]
            self.users[uid] = {**self.users.get(uid, {}), **payload, "id": uid}
            return None
        raise AssertionError(f"unexpected PUT {path}")

    def delete(self, path: str, payload=None):
        if path.endswith("/role-mappings/realm"):
            uid = path.split("/")[2]
            for item in payload or []:
                self.user_roles.get(uid, set()).discard(item["name"])
            return None
        if "/groups/" in path:
            uid = path.split("/")[2]
            gid = path.rsplit("/", 1)[-1]
            name = next(n for n, g in self.groups.items() if g["id"] == gid)
            self.user_groups.get(uid, set()).discard(name)
            return None
        raise AssertionError(f"unexpected DELETE {path}")


def test_seed_is_idempotent_and_does_not_rotate_passwords(monkeypatch):
    fake = _FakeAdmin()
    monkeypatch.setattr(seed, "admin_token", lambda *a, **k: "token")
    monkeypatch.setattr(seed, "AdminClient", lambda *a, **k: fake)

    passwords = {ident.username: f"secret-for-{ident.username}" for ident in seed.IDENTITIES}
    first = seed.seed(
        base_url="http://127.0.0.1:8081",
        bootstrap_username="bootstrap",
        bootstrap_password="bootstrap-secret",
        passwords=passwords,
        rotate_passwords=False,
    )
    assert set(first) == {ident.username for ident in seed.IDENTITIES}
    assert all(action == "created" for action in first.values())
    assert len(fake.users) == 3
    assert len(fake.passwords_set) == 3

    user_count = len(fake.users)
    first_ids = set(fake.users)
    second = seed.seed(
        base_url="http://127.0.0.1:8081",
        bootstrap_username="bootstrap",
        bootstrap_password="bootstrap-secret",
        passwords=passwords,
        rotate_passwords=False,
    )
    assert all(action == "updated" for action in second.values())
    assert len(fake.users) == user_count
    assert set(fake.users) == first_ids
    assert len(fake.passwords_set) == 3

    renter_id = "user-renter"
    leaser_id = "user-leaser"
    admin_id = "user-admin"
    assert fake.user_roles[renter_id] == {"renter"}
    assert fake.user_groups[renter_id] == {"renter"}
    assert fake.user_roles[leaser_id] == {"host"}
    assert fake.user_groups[leaser_id] == {"host"}
    assert fake.user_roles[admin_id] == {"admin"}
    assert fake.user_groups[admin_id] == set()
    assert "leaser" not in fake.roles
    assert "leaser" not in fake.groups


def test_seed_rotates_password_only_when_asked(monkeypatch):
    fake = _FakeAdmin()
    monkeypatch.setattr(seed, "admin_token", lambda *a, **k: "token")
    monkeypatch.setattr(seed, "AdminClient", lambda *a, **k: fake)
    passwords = {ident.username: "first" for ident in seed.IDENTITIES}
    seed.seed(
        base_url="http://127.0.0.1:8081",
        bootstrap_username="bootstrap",
        bootstrap_password="bootstrap-secret",
        passwords=passwords,
    )
    seed.seed(
        base_url="http://127.0.0.1:8081",
        bootstrap_username="bootstrap",
        bootstrap_password="bootstrap-secret",
        passwords=passwords,
        rotate_passwords=True,
    )
    assert len(fake.passwords_set) == 6


def test_reconcile_strips_cross_role_mappings(monkeypatch):
    fake = _FakeAdmin()
    monkeypatch.setattr(seed, "admin_token", lambda *a, **k: "token")
    monkeypatch.setattr(seed, "AdminClient", lambda *a, **k: fake)
    passwords = {ident.username: "first" for ident in seed.IDENTITIES}
    seed.seed(
        base_url="http://127.0.0.1:8081",
        bootstrap_username="bootstrap",
        bootstrap_password="bootstrap-secret",
        passwords=passwords,
    )
    admin_id = "user-admin"
    fake.user_roles[admin_id].add("renter")
    fake.user_roles[admin_id].add("host")
    fake.user_groups[admin_id].add("renter")
    seed.seed(
        base_url="http://127.0.0.1:8081",
        bootstrap_username="bootstrap",
        bootstrap_password="bootstrap-secret",
        passwords=passwords,
    )
    assert fake.user_roles[admin_id] == {"admin"}
    assert fake.user_groups[admin_id] == set()


def test_deploy_wait_retries_then_succeeds(monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    now = [0.0]
    calls = []
    monkeypatch.setattr(seed.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(seed.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))

    def open_url(url, timeout):
        calls.append((url, timeout))
        if len(calls) == 1:
            raise OSError("synthetic network failure")
        return nullcontext(SimpleNamespace(status=200))

    monkeypatch.setattr(seed.urllib.request, "urlopen", open_url)
    seed.wait_until_ready("http://127.0.0.1:8081/", 5)
    assert len(calls) == 2
    assert calls[0] == ("http://127.0.0.1:8081/realms/master", 2.0)


def test_deploy_wait_timeout_is_bounded_and_sanitized(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(seed.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(seed.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))

    def unavailable(*args, **kwargs):
        raise OSError("synthetic-secret-must-not-appear")

    monkeypatch.setattr(seed.urllib.request, "urlopen", unavailable)
    with pytest.raises(seed.SeedError, match="readiness timed out") as error:
        seed.wait_until_ready("http://127.0.0.1:8081", 3)
    assert now[0] == 3
    assert "synthetic-secret" not in str(error.value)


def test_deploy_missing_password_fails_before_wait(monkeypatch, capsys):
    monkeypatch.delenv("PANOPTICON_TEST_RENTER_PASSWORD", raising=False)
    monkeypatch.setattr(seed, "wait_until_ready", lambda *_: pytest.fail("must validate credentials first"))
    assert seed.main(["--wait-seconds", "60"]) == 1
    assert "seed failed" in capsys.readouterr().err


def test_deploy_wait_precedes_seed_and_does_not_rotate(monkeypatch):
    events = []
    monkeypatch.setattr(seed, "require_passwords", lambda: {})
    monkeypatch.setattr(seed, "require_env", lambda name: "synthetic")
    monkeypatch.setenv("KEYCLOAK_URL", "http://127.0.0.1:8081")
    monkeypatch.setattr(seed, "wait_until_ready", lambda url, seconds: events.append(("wait", seconds)))

    def run_seed(**kwargs):
        events.append(("seed", kwargs["rotate_passwords"]))
        return {}

    monkeypatch.setattr(seed, "seed", run_seed)
    assert seed.main(["--wait-seconds", "60"]) == 0
    assert events == [("wait", 60), ("seed", False)]


def test_negative_wait_is_rejected():
    with pytest.raises(SystemExit):
        seed.parse_args(["--wait-seconds", "-1"])


def test_deploy_timeout_prevents_seed(monkeypatch, capsys):
    monkeypatch.setattr(seed, "require_passwords", lambda: {})
    monkeypatch.setattr(seed, "require_env", lambda name: "synthetic")
    monkeypatch.setenv("KEYCLOAK_URL", "http://127.0.0.1:8081")

    def timeout(*_):
        raise seed.SeedError("Keycloak readiness timed out")

    monkeypatch.setattr(seed, "wait_until_ready", timeout)
    monkeypatch.setattr(seed, "seed", lambda **_: pytest.fail("seed must not run after timeout"))
    assert seed.main(["--wait-seconds", "60"]) == 1
    assert "readiness timed out" in capsys.readouterr().err
