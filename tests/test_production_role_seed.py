"""Production role-only seed vs development user seeder."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from api.common.seeder_utils import get_seed_roles
from api.domain.enum.permission import Permission
from api.domain.enum.role import RoleType
from api.infrastructure.persistence.seeder import apply_seed, seed_platform_roles


class FakeRoleRepo:
    def __init__(self) -> None:
        self.roles: dict[str, SimpleNamespace] = {}
        self.created_names: list[str] = []

    async def count(self) -> int:
        return len(self.roles)

    async def single_or_none(self, name=None):
        if name is None:
            return None
        key = name.value if isinstance(name, RoleType) else str(name)
        return self.roles.get(key)

    async def find_platform_role(self, name: str):
        key = name.value if isinstance(name, RoleType) else str(name)
        for role in self.roles.values():
            if str(role.name).lower() != key.lower():
                continue
            if getattr(role, "tenant_id", None) is not None:
                continue
            return role
        return None

    async def insert_platform_role_if_absent(self, name: str, description: str | None) -> bool:
        if await self.find_platform_role(name) is not None:
            return False
        await self.create(SimpleNamespace(name=name, description=description, tenant_id=None))
        return True

    async def create(self, data):
        rid = uuid.uuid4()
        name = str(data.name)
        self.roles[name] = SimpleNamespace(
            id=rid,
            name=name,
            description=data.description,
            permissions=[],
        )
        self.created_names.append(name)
        return rid

    async def update(self, role_id: str, data):
        for role in self.roles.values():
            if str(role.id) == str(role_id):
                if data.name is not None:
                    role.name = str(data.name)
                if data.description is not None:
                    role.description = data.description
                role.permissions = list(data.permissions)
                return role
        return None


class FakeUserRepo:
    def __init__(self) -> None:
        self.created: list[object] = []
        self.users: dict[str, SimpleNamespace] = {}

    async def count(self) -> int:
        return len(self.users)

    async def single_or_none(self, email=None, **_kwargs):
        if email is None:
            return None
        return self.users.get(str(email))

    async def create(self, data):
        self.created.append(data)
        uid = uuid.uuid4()
        self.users[str(data.email)] = SimpleNamespace(id=uid, email=str(data.email))
        return uid

    async def update(self, user_id: str, data):
        return None


def _perm_values(permissions) -> set[str]:
    return {
        p.value if isinstance(p, Permission) else str(p) for p in permissions or []
    }


@pytest.mark.asyncio
async def test_production_role_only_seed_creates_guest_and_admin() -> None:
    roles = FakeRoleRepo()
    users = FakeUserRepo()

    await apply_seed(roles, users, fastapi_env="production")

    expected = {_role.name.value for _role in get_seed_roles()}
    assert expected == {"admin", "user", "guest", "billing_manager"}
    assert set(roles.roles) == expected
    assert "guest" in roles.roles
    assert "admin" in roles.roles
    assert Permission.HOST_MANAGE_TENANTS in roles.roles["admin"].permissions
    assert users.created == []


@pytest.mark.asyncio
async def test_development_seeder_still_runs_in_development(monkeypatch) -> None:
    roles = FakeRoleRepo()
    users = FakeUserRepo()
    called = {"dev": False}

    async def _mark(*_args, **_kwargs):
        called["dev"] = True

    monkeypatch.setattr(
        "api.infrastructure.persistence.seeder.seed_development_users",
        _mark,
    )

    await apply_seed(roles, users, fastapi_env="development")

    assert called["dev"] is True
    assert "guest" in roles.roles
    assert "admin" in roles.roles


@pytest.mark.asyncio
async def test_development_seeder_does_not_run_in_production(monkeypatch) -> None:
    roles = FakeRoleRepo()
    users = FakeUserRepo()
    called = {"dev": False}

    async def _boom(*_args, **_kwargs):
        called["dev"] = True
        raise AssertionError("development user seeder must not run in production")

    monkeypatch.setattr(
        "api.infrastructure.persistence.seeder.seed_development_users",
        _boom,
    )

    await apply_seed(roles, users, fastapi_env="production")

    assert called["dev"] is False
    assert users.created == []
    assert "guest" in roles.roles
    assert "admin" in roles.roles


@pytest.mark.asyncio
async def test_platform_role_seed_is_idempotent_and_attaches_host_manage() -> None:
    roles = FakeRoleRepo()
    await seed_platform_roles(roles)
    first_ids = {name: role.id for name, role in roles.roles.items()}
    created_once = list(roles.created_names)

    await seed_platform_roles(roles)

    assert roles.created_names == created_once
    assert {name: role.id for name, role in roles.roles.items()} == first_ids
    assert Permission.HOST_MANAGE_TENANTS.value in _perm_values(
        roles.roles["admin"].permissions
    )
