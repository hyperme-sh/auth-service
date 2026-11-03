"""Human identity comes from an administrator binding, never authentication alone."""

import copy
import importlib.util
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("account_types", ROOT / "infra/keycloak/account_types.py")
accounts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(accounts)


class Admin:
    def __init__(self):
        self.profile = {"attributes": [{"name": "email", "permissions": {"edit": ["user"]}}], "groups": [{"name": "existing"}]}
        self.mappers = []
        self.users = {}

    def get(self, path):
        if path == "/users/profile":
            return copy.deepcopy(self.profile)
        if path.endswith("protocol-mappers/models"):
            return copy.deepcopy(self.mappers)
        if path.startswith("/users/"):
            return copy.deepcopy(self.users[path.split("/")[-1]])
        raise AssertionError(path)

    def put(self, path, body):
        if path == "/users/profile":
            self.profile = copy.deepcopy(body)
        elif "protocol-mappers" in path:
            self.mappers = [copy.deepcopy(body) if m["id"] == body["id"] else m for m in self.mappers]
        else:
            self.users[path.split("/")[-1]] = copy.deepcopy(body)

    def post(self, path, body):
        self.mappers.append({**copy.deepcopy(body), "id": str(uuid.uuid4())})


def test_profile_blocks_self_classification_and_preserves_other_attributes():
    current = Admin().profile
    protected = accounts.protected_profile(current)
    assert current["attributes"] == [{"name": "email", "permissions": {"edit": ["user"]}}]
    assert protected["groups"] == current["groups"]
    assert protected["attributes"][0] == current["attributes"][0]
    attribute = protected["attributes"][1]
    assert attribute["permissions"] == {"view": ["admin"], "edit": ["admin"]}
    assert attribute["validations"]["options"]["options"] == ["human", "service"]
    assert not attribute.get("required")
    assert accounts.protected_profile(protected) == protected


def test_frontend_mapper_reconciles_without_duplicates_or_relying_on_server_defaults():
    admin = Admin()
    accounts.ensure_mapper(admin, "frontend", accounts.HUMAN_MAPPER)
    admin.mappers[0]["config"]["introspection.token.claim"] = "true"
    first_id = admin.mappers[0]["id"]
    accounts.ensure_mapper(admin, "frontend", accounts.HUMAN_MAPPER)
    assert len(admin.mappers) == 1 and admin.mappers[0]["id"] == first_id
    admin.mappers[0]["config"]["user.attribute"] = "untrusted"
    accounts.ensure_mapper(admin, "frontend", accounts.HUMAN_MAPPER)
    assert admin.mappers[0]["config"]["user.attribute"] == "account_type"


def test_conflicting_mapper_cannot_override_account_classification():
    admin = Admin()
    admin.mappers = [{"name": name, "config": {"claim.name": "account_type"}} for name in ["first", "second"]]
    with pytest.raises(accounts.AccountTypeError, match="Duplicate"):
        accounts.ensure_mapper(admin, "frontend", accounts.HUMAN_MAPPER)


@pytest.mark.parametrize("kind", ["human", "service"])
def test_explicit_classification_preserves_user_metadata(kind):
    admin = Admin()
    user_id = str(uuid.uuid4())
    admin.users[user_id] = {"id": user_id, "username": "named-account", "attributes": {"existing": ["keep"]}}
    accounts.classify(admin, user_id, kind)
    assert admin.users[user_id]["attributes"] == {"existing": ["keep"], "account_type": [kind]}


def test_client_service_account_cannot_be_promoted_to_human():
    admin = Admin()
    user_id = str(uuid.uuid4())
    admin.users[user_id] = {"id": user_id, "username": "service-account-ai", "serviceAccountClientId": "ai"}
    with pytest.raises(accounts.AccountTypeError):
        accounts.classify(admin, user_id, "human")
    assert "attributes" not in admin.users[user_id]


def test_realm_import_classifies_people_and_shared_automation_separately():
    import json
    realm = json.loads((ROOT / "infra/keycloak/import/controlplane-realm.json").read_text())
    profile = json.loads(realm["components"]["org.keycloak.userprofile.UserProfileProvider"][0]["config"]["kc.user.profile.config"][0])
    attribute = next(a for a in profile["attributes"] if a["name"] == "account_type")
    assert attribute == accounts.ATTRIBUTE
    users = {u["username"]: u for u in realm["users"]}
    assert users["chris@fyberlabs.com"]["attributes"]["account_type"] == ["human"]
    for username in ["renter", "leaser", "admin"]:
        assert users[username]["attributes"]["account_type"] == ["service"]
    for client in realm["clients"]:
        if client["clientId"] == "controlplane-frontend":
            assert accounts.HUMAN_MAPPER in client["protocolMappers"]
            assert accounts.AMR_MAPPER in client["protocolMappers"]
        elif client.get("serviceAccountsEnabled"):
            assert accounts.SERVICE_MAPPER in client["protocolMappers"]
