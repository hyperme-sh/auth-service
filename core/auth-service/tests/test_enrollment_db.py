"""Enrollment job against Postgres: bind, grant, membership row, no device.

Does not POST /auth/switch-tenant, checkout, or live pan-test.
Membership visibility is checked via authorize_tenant_switch in-process.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections import namedtuple

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.infrastructure.persistence.db_session import (
    configure_session_maker,
    reset_db_session,
    set_db_session,
)
from api.infrastructure.persistence.tenant_guc import set_current_tenant_id_guc
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from auth_service.enrollment import (
    HELD_HOST,
    HELD_ORG_ADMIN,
    HELD_RENTER,
    NETWORK_ADMIN_SEED_EMAIL,
    grant_held_roles,
)
from auth_service.schemas import AuthMeResponse
from auth_service.tenant_switch import authorize_tenant_switch
from auth_service.wallet_bind import bind_wallet, get_wallet_binding, issue_siwe_nonce
from controlplane_db.models import ApiKey, Group, HypermeshDevice, Role, User, UserGroupMembership
from controlplane_db.session import normalize_database_url
from panopticon_tests.fixtures.postgres import (
    async_db_url,
    normalize_sync_sqlalchemy_url,
    run_alembic_upgrade,
)

Seed = namedtuple("Seed", ["tenant_id"])


@pytest.fixture(scope="session")
def require_docker() -> None:
    if os.environ.get("SKIP_TESTCONTAINERS", "").lower() in ("1", "true", "yes"):
        pytest.skip("SKIP_TESTCONTAINERS is set")
    try:
        import docker

        docker.from_env().ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Docker not available for testcontainers: {exc}")


@pytest.fixture(scope="session")
def postgres_container(require_docker: None):
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16-alpine") as pg:
        yield pg


@pytest.fixture(scope="session")
def migrated_sync_url(postgres_container) -> str:
    url = normalize_sync_sqlalchemy_url(postgres_container.get_connection_url())
    run_alembic_upgrade(url)
    return url


@pytest.fixture(scope="session")
def seed(migrated_sync_url: str) -> Seed:
    tenant_id = MARKETPLACE_TENANT_ID
    eng = create_engine(migrated_sync_url)
    with eng.begin() as cx:
        # Alembic 0012 already INSERTs this marketplace tenant.
        cx.execute(
            text(
                "INSERT INTO tenants (id, name, is_active) "
                "VALUES (:id, :n, true) ON CONFLICT (id) DO NOTHING"
            ),
            {"id": tenant_id, "n": "marketplace"},
        )
    return Seed(tenant_id)


@pytest.fixture
async def db_session(migrated_sync_url: str, seed: Seed):
    db_url = async_db_url(migrated_sync_url)
    engine = create_async_engine(normalize_database_url(db_url))
    maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    configure_session_maker(maker)
    async with maker() as session:
        token = set_db_session(session)
        await set_current_tenant_id_guc(session, seed.tenant_id)
        try:
            yield session
            await session.commit()
        finally:
            reset_db_session(token)
    await engine.dispose()


def _sign(message: str, key: str) -> str:
    return Account.from_key(key).sign_message(encode_defunct(text=message)).signature.hex()


def _assert_no_printed_secrets(payload: dict) -> None:
    dumped = json.dumps(payload)
    for needle in (
        "signature",
        "secret_plaintext",
        "private_key",
        "enroll_token",
        "refresh_token",
    ):
        assert needle not in dumped
    assert "api_key_prefix" in dumped or payload.get("renter") is None


@pytest.mark.asyncio
async def test_siwe_binds_wallet_onto_identified_user(db_session):
    acct = Account.create()
    person = AuthMeResponse(sub="kc-bind-1", email="bind@example.com")
    nonce = issue_siwe_nonce(person, address=acct.address)
    bound = await bind_wallet(
        db_session,
        person,
        message=nonce.message,
        signature=_sign(nonce.message, acct.key.hex()),
    )
    assert bound.wallet_address == acct.address
    assert bound.keycloak_sub == "kc-bind-1"
    fetched = await get_wallet_binding(db_session, "kc-bind-1")
    assert fetched is not None
    assert fetched.wallet_address == acct.address
    row = (await db_session.execute(select(User))).scalars().all()
    # Bind is not a second user.
    assert all(u.email != acct.address for u in row)


@pytest.mark.asyncio
async def test_renter_grant_membership_is_visible_to_switch_tenant(db_session, seed):
    person = AuthMeResponse(
        sub="kc-renter-1",
        email="enroll-renter@example.com",
        groups=["renter"],
        roles=["renter"],
    )
    existing = (
        await db_session.execute(
            select(User).where(
                User.tenant_id == MARKETPLACE_TENANT_ID,
                User.email == "enroll-renter@example.com",
            )
        )
    ).scalars().all()
    assert existing == []

    result = await grant_held_roles(
        db_session,
        person,
        requested=[HELD_RENTER],
    )
    public = result.as_public_dict()
    _assert_no_printed_secrets(public)
    assert result.granted == (HELD_RENTER,)
    assert HELD_HOST not in result.granted
    assert result.renter is not None
    assert result.renter.tenant_membership is True
    assert result.renter.group == "renter"
    assert result.renter.can_checkout is True
    assert result.renter.can_see_leases is True
    assert result.renter.can_mint_keys is True
    assert result.host is None
    assert result.renter.api_key_prefix
    assert public["renter"]["api_key_prefix"] == result.renter.api_key_prefix
    assert "api_key" not in public["renter"]

    assert person.tenant_id is None
    grant = await authorize_tenant_switch(person, seed.tenant_id, session=db_session)
    assert grant is not None

    users = (
        await db_session.execute(
            select(User).where(
                User.tenant_id == MARKETPLACE_TENANT_ID,
                User.email == "enroll-renter@example.com",
            )
        )
    ).scalars().all()
    assert seed.tenant_id == MARKETPLACE_TENANT_ID
    assert len(users) == 1
    assert users[0].tenant_id == MARKETPLACE_TENANT_ID
    assert users[0].email == "enroll-renter@example.com"
    keys = (
        await db_session.execute(
            select(ApiKey).where(ApiKey.tenant_id == seed.tenant_id)
        )
    ).scalars().all()
    assert len(keys) == 1
    assert keys[0].purpose == "renter"
    assert keys[0].key_prefix == result.renter.api_key_prefix


@pytest.mark.asyncio
async def test_new_keycloak_user_without_token_groups_gets_renter_not_org_admin(
    db_session, seed
):
    person = AuthMeResponse(
        sub="kc-fresh-1",
        email="fresh-renter@example.com",
        groups=[],
        roles=[],
    )
    result = await grant_held_roles(
        db_session,
        person,
        requested=[HELD_RENTER, HELD_ORG_ADMIN],
    )
    assert result.granted == (HELD_RENTER,)
    assert HELD_ORG_ADMIN in result.refused
    assert result.renter is not None
    assert result.org_admin is None
    grant = await authorize_tenant_switch(person, seed.tenant_id, session=db_session)
    assert grant is not None


@pytest.mark.asyncio
async def test_host_grant_is_org_membership_not_device_enroll(db_session, seed):
    person = AuthMeResponse(
        sub="kc-host-1",
        email="enroll-host@example.com",
        groups=["host"],
        roles=["host"],
    )
    before = await db_session.execute(
        select(func.count()).select_from(HypermeshDevice).where(
            HypermeshDevice.tenant_id == seed.tenant_id
        )
    )
    result = await grant_held_roles(
        db_session,
        person,
        tenant_id=seed.tenant_id,
        requested=[HELD_HOST],
    )
    after = await db_session.execute(
        select(func.count()).select_from(HypermeshDevice).where(
            HypermeshDevice.tenant_id == seed.tenant_id
        )
    )
    assert int(before.scalar_one()) == int(after.scalar_one()) == 0
    assert result.host is not None
    assert result.host.device_enrolled is False
    assert result.device_enrolled is False
    assert result.renter is None
    groups = (
        await db_session.execute(
            select(Group.name)
            .join(UserGroupMembership, UserGroupMembership.group_id == Group.id)
            .join(User, User.id == UserGroupMembership.user_id)
            .where(User.email == "enroll-host@example.com")
        )
    ).scalars().all()
    assert "host" in {n.lower() for n in groups}
    public = result.as_public_dict()
    assert "enroll_token" not in json.dumps(public)


@pytest.mark.asyncio
async def test_org_admin_grant_is_not_network_admin_seed(db_session, seed):
    person = AuthMeResponse(
        sub="kc-org-admin-1",
        email="org-admin@example.com",
        roles=["admin"],
    )
    result = await grant_held_roles(
        db_session,
        person,
        tenant_id=seed.tenant_id,
        requested=[HELD_ORG_ADMIN],
    )
    assert result.org_admin is not None
    assert result.org_admin.email == "org-admin@example.com"
    assert result.org_admin.email != NETWORK_ADMIN_SEED_EMAIL
    assert result.org_admin.network_admin_seed is False
    assert result.org_admin.keycloak_bootstrap_admin is False
    assert result.org_admin.portal_role == "admin"
    assert result.renter is None
    assert result.host is None


@pytest.mark.asyncio
async def test_renter_and_host_grant_does_not_grant_org_admin(db_session, seed):
    person = AuthMeResponse(
        sub="kc-marketplace-1",
        email="marketplace-enroll@example.com",
        groups=["renter", "host"],
        roles=["renter", "host", "admin"],
    )
    result = await grant_held_roles(
        db_session,
        person,
        tenant_id=seed.tenant_id,
        requested=[HELD_RENTER, HELD_HOST, HELD_ORG_ADMIN],
    )
    assert set(result.granted) == {HELD_RENTER, HELD_HOST}
    assert HELD_ORG_ADMIN in result.refused
    assert result.renter is not None
    assert result.host is not None
    assert result.org_admin is None
    assert result.device_enrolled is False
    grant = await authorize_tenant_switch(person, seed.tenant_id, session=db_session)
    assert grant is not None


@pytest.mark.asyncio
async def test_enrollment_creates_tenant_scoped_user_role(db_session, seed):
    """A platform "user" row stays put. Enrollment adds the marketplace one."""

    platform_id = uuid.uuid4()
    await db_session.execute(text("SELECT set_config('app.current_tenant_id', '', true)"))
    await db_session.execute(
        text(
            """
            INSERT INTO roles (id, tenant_id, name, permissions)
            VALUES (:id, NULL, 'user', '[]'::jsonb)
            """
        ),
        {"id": platform_id},
    )
    person = AuthMeResponse(
        sub="kc-tenant-role-1",
        email="tenant-role@example.com",
        groups=["renter"],
        roles=["renter"],
    )
    await grant_held_roles(db_session, person, requested=[HELD_RENTER])
    roles = (
        await db_session.execute(select(Role).where(func.lower(Role.name) == "user"))
    ).scalars().all()
    tenant_roles = [role for role in roles if role.tenant_id == seed.tenant_id]
    platform_roles = [role for role in roles if role.tenant_id is None]
    assert len(tenant_roles) == 1
    assert tenant_roles[0].id != platform_id
    assert {role.id for role in platform_roles} == {platform_id}
    group = (
        await db_session.execute(
            select(Group).where(
                Group.tenant_id == seed.tenant_id,
                func.lower(Group.name) == "renter",
            )
        )
    ).scalar_one()
    assert group.role_id == tenant_roles[0].id


@pytest.mark.asyncio
async def test_concurrent_enrollment_creates_one_tenant_role(migrated_sync_url, seed):
    tenant_id = uuid.uuid4()
    eng = create_engine(migrated_sync_url)
    with eng.begin() as cx:
        cx.execute(
            text(
                "INSERT INTO tenants (id, name, is_active) VALUES (:id, :name, true)"
            ),
            {"id": tenant_id, "name": f"enroll-{tenant_id.hex[:8]}"},
        )

    db_url = async_db_url(migrated_sync_url)
    engine = create_async_engine(normalize_database_url(db_url), pool_size=8, max_overflow=4)
    maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)

    async def _enroll(n: int) -> None:
        async with maker() as session:
            person = AuthMeResponse(
                sub=f"kc-conc-{n}",
                email=f"conc-{n}@example.com",
                groups=["renter"],
                roles=["renter"],
            )
            await grant_held_roles(
                session,
                person,
                tenant_id=tenant_id,
                requested=[HELD_RENTER],
            )
            await session.commit()

    try:
        await asyncio.gather(*[_enroll(n) for n in range(6)])
        async with maker() as session:
            roles = (
                await session.execute(
                    select(Role).where(
                        Role.tenant_id == tenant_id,
                        func.lower(Role.name) == "user",
                    )
                )
            ).scalars().all()
            groups = (
                await session.execute(
                    select(Group).where(
                        Group.tenant_id == tenant_id,
                        func.lower(Group.name) == "renter",
                    )
                )
            ).scalars().all()
            members = (
                await session.execute(
                    select(func.count())
                    .select_from(UserGroupMembership)
                    .where(UserGroupMembership.tenant_id == tenant_id)
                )
            ).scalar_one()
    finally:
        await engine.dispose()

    assert len(roles) == 1
    assert len(groups) == 1
    assert groups[0].role_id == roles[0].id
    assert int(members) == 6


@pytest.mark.asyncio
async def test_enrollment_http_bind_and_grant(migrated_sync_url, seed, monkeypatch):
    from api.core import config as api_config
    from asgi_lifespan import LifespanManager
    import httpx

    db_url = async_db_url(migrated_sync_url)
    if "+psycopg" in db_url:
        db_url = db_url.replace("postgresql+psycopg://", "postgresql://", 1)
    monkeypatch.setattr(api_config.settings, "database_url", db_url)
    monkeypatch.setattr(api_config.settings, "kafka_bootstrap_servers", None)
    monkeypatch.setattr(api_config.settings, "oidc_require_mfa", False)
    monkeypatch.setattr(api_config.settings, "auth_token_validation_mode", "jwt")

    from auth_service.app import create_app
    from auth_service import deps

    person = AuthMeResponse(
        sub="kc-http-1",
        email="http-enroll@example.com",
        groups=["renter"],
        roles=["renter"],
    )
    acct = Account.create()

    async def _user() -> AuthMeResponse:
        return person

    async def _claims() -> dict:
        # Raw OIDC: identify only. No tenant_id on the Keycloak token.
        return {
            "sub": person.sub,
            "email": person.email,
            "realm_access": {"roles": ["renter"]},
            "groups": ["renter"],
            "scope": "openid",
        }

    app = create_app(test_event_sink=[], enable_db_middleware=True)
    app.dependency_overrides[deps.get_current_auth_user] = _user
    app.dependency_overrides[deps.get_access_token_claims] = _claims
    try:
        async with LifespanManager(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://localhost"
            ) as client:
                nonce = await client.post(
                    "/auth/siwe/nonce",
                    headers={"Authorization": "Bearer test"},
                    json={"address": acct.address, "chain_id": 1},
                )
                assert nonce.status_code == 200, nonce.text
                message = nonce.json()["message"]
                bind = await client.post(
                    "/auth/siwe/bind",
                    headers={"Authorization": "Bearer test"},
                    json={
                        "message": message,
                        "signature": _sign(message, acct.key.hex()),
                    },
                )
                assert bind.status_code == 200, bind.text
                body = bind.json()
                assert body["wallet_address"] == acct.address
                assert body["keycloak_sub"] == "kc-http-1"
                assert "signature" not in body
                grant = await client.post(
                    "/auth/enrollment/grant",
                    headers={
                        "Authorization": "Bearer test",
                        "X-Tenant-ID": str(seed.tenant_id),
                    },
                    json={
                        "tenant_id": str(seed.tenant_id),
                        "held_roles": ["renter"],
                    },
                )
                assert grant.status_code == 200, grant.text
                granted = grant.json()
                _assert_no_printed_secrets(granted)
                assert granted["granted"] == ["renter"]
                assert granted["renter"]["tenant_membership"] is True
                assert granted["device_enrolled"] is False
                assert "tenant_id" not in (await _claims())
    finally:
        app.dependency_overrides.clear()
