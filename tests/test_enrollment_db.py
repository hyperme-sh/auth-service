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
from user_service.identity_enrollment import (
    EnrollmentError,
    HELD_HOST,
    HELD_ORG_ADMIN,
    HELD_RENTER,
    NETWORK_ADMIN_SEED_EMAIL,
    grant_held_roles,
)
from auth_service.schemas import AuthMeResponse
from auth_service.identity_owner import call as real_identity_owner_call
from user_service.identity_tenant_switch import authorize_tenant_switch
from auth_service.wallet_bind import bind_wallet, issue_siwe_nonce
from user_service.identity_wallet_bind import get_wallet_binding
from controlplane_db.models import (
    ApiKey,
    Group,
    Organization,
    Role,
    User,
    UserGroupMembership,
)
from controlplane_db.session import normalize_database_url
from controlplane_db.migrations import upgrade


def async_db_url(url):
    return url.replace("postgresql+psycopg://", "postgresql+asyncpg://")


def normalize_sync_sqlalchemy_url(url):
    return normalize_database_url(url).replace("+asyncpg", "+psycopg")


Seed = namedtuple("Seed", ["tenant_id"])


@pytest.fixture(scope="session")
def require_docker() -> None:
    if os.environ.get("SKIP_TESTCONTAINERS", "").lower() in ("1", "true", "yes"):
        pytest.fail("Owner integration tests require Docker; skipping is not acceptance")
    try:
        import docker

        docker.from_env().ping()
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"Docker required for owner integration: {type(exc).__name__}")


@pytest.fixture(scope="session")
def postgres_container(require_docker: None):
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16-alpine@sha256:20edbde7749f822887a1a022ad526fde0a47d6b2be9a8364433605cf65099416", driver="psycopg") as pg:
        yield pg


@pytest.fixture(scope="session")
def migrated_sync_url(postgres_container) -> str:
    url = normalize_sync_sqlalchemy_url(postgres_container.get_connection_url())
    upgrade(url, chains=["platform", "events", "hypermesh"])
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


@pytest.fixture(autouse=True)
def host_owner_http(monkeypatch):
    import httpx
    from user_service import identity_enrollment as enrollment
    from auth_service.host_binding_client import HttpHostBindingClient
    token = "owner-test-token-" + "x" * 40
    def owner(request):
        payload = json.loads(request.content)
        assert request.headers["X-Tenant-ID"] == payload["tenant_id"]
        assert request.headers["X-Internal-Token"] == token
        org = uuid.uuid5(uuid.NAMESPACE_URL, "test-owner:" + payload["tenant_id"] + ":" + payload["subject"])
        return httpx.Response(200, json=payload | {"organization_id": str(org)})
    client = HttpHostBindingClient("https://host-owner.test", token, httpx.MockTransport(owner))
    monkeypatch.setattr(enrollment, "host_binding_client", lambda: client)


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
async def test_siwe_binds_wallet_onto_identified_user(db_session, base_wallet_verifier, nonce_store):
    acct = Account.create()
    person = AuthMeResponse(sub="kc-bind-1", email="bind@example.com")
    nonce = await issue_siwe_nonce(person, address=acct.address, store=nonce_store)
    bound = await bind_wallet(
        db_session,
        person,
        message=nonce.message,
        signature=_sign(nonce.message, acct.key.hex()),
        store=nonce_store,
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
    assert grant.role_name == "user"
    assert grant.permissions == ()
    assert grant.groups == ("renter",)

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
        text("SELECT count(*) FROM hypermesh_devices WHERE tenant_id = :tenant_id"),
        {"tenant_id": seed.tenant_id}
    )
    result = await grant_held_roles(
        db_session,
        person,
        tenant_id=seed.tenant_id,
        requested=[HELD_HOST],
    )
    after = await db_session.execute(
        text("SELECT count(*) FROM hypermesh_devices WHERE tenant_id = :tenant_id"),
        {"tenant_id": seed.tenant_id}
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
        tenant_id=seed.tenant_id,
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
async def test_enrollment_http_bind_and_grant(migrated_sync_url, seed, monkeypatch, base_wallet_verifier, siwe_redis_url):
    monkeypatch.setenv("AUTH_SIWE_REDIS_URL", siwe_redis_url)
    from api.core import config as api_config
    from asgi_lifespan import LifespanManager
    import httpx

    db_url = async_db_url(migrated_sync_url)
    if "+psycopg" in db_url:
        db_url = db_url.replace("postgresql+psycopg://", "postgresql://", 1)
    monkeypatch.setattr(api_config.settings, "database_url", db_url)
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
                    json={"address": acct.address, "chain_id": 84532},
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


@pytest.mark.asyncio
async def test_host_organizations_are_bound_to_identity_not_oldest_org(db_session, seed):
    unrelated = Organization(
        id=uuid.uuid4(), tenant_id=seed.tenant_id, legal_name=f"Unrelated {uuid.uuid4()}"
    )
    db_session.add(unrelated)
    await db_session.flush()
    suffix = uuid.uuid4().hex
    alice = AuthMeResponse(sub=f"host-alice-{suffix}", email=f"alice-{suffix}@example.com")
    bob = AuthMeResponse(sub=f"host-bob-{suffix}", email=f"bob-{suffix}@example.com")
    first = await grant_held_roles(db_session, alice, requested=[HELD_HOST])
    second = await grant_held_roles(db_session, bob, requested=[HELD_HOST])
    again = await grant_held_roles(db_session, alice, requested=[HELD_HOST])
    assert first.host is not None and second.host is not None and again.host is not None
    assert first.host.organization_id == again.host.organization_id
    assert len({first.host.organization_id, second.host.organization_id, unrelated.id}) == 3



@pytest.mark.asyncio
async def test_email_changes_do_not_transfer_host_organization(db_session):
    suffix = uuid.uuid4().hex
    alice = AuthMeResponse(sub=f"stable-{suffix}", email=f"before-{suffix}@example.com")
    first = await grant_held_roles(db_session, alice, requested=[HELD_HOST])
    renamed = alice.model_copy(update={"email": f"after-{suffix}@example.com"})
    again = await grant_held_roles(db_session, renamed, requested=[HELD_HOST])
    # Another subject cannot use Alice's still-bound old email for membership.
    other = AuthMeResponse(sub=f"other-{suffix}", email=alice.email)
    with pytest.raises(EnrollmentError, match="bound to another identity"):
        await grant_held_roles(db_session, other, requested=[HELD_HOST])
    separate = await grant_held_roles(db_session,
        other.model_copy(update={"email": f"separate-{suffix}@example.com"}), requested=[HELD_HOST])
    assert first.host and again.host and separate.host
    assert first.host.organization_id == again.host.organization_id
    assert separate.host.organization_id != first.host.organization_id


@pytest.mark.asyncio
async def test_same_identity_has_separate_host_organizations_per_tenant(db_session, seed):
    other_tenant = uuid.uuid4()
    await db_session.execute(
        text("INSERT INTO tenants (id, name, is_active) VALUES (:id, :name, true)"),
        {"id": other_tenant, "name": f"host-other-{other_tenant}"},
    )
    suffix = uuid.uuid4().hex
    person = AuthMeResponse(sub=f"multi-{suffix}", email=f"multi-{suffix}@example.com")
    first = await grant_held_roles(db_session, person, tenant_id=seed.tenant_id, requested=[HELD_HOST])
    second = await grant_held_roles(db_session, person, tenant_id=other_tenant, requested=[HELD_HOST])
    assert first.host and second.host
    assert first.host.organization_id != second.host.organization_id


@pytest.mark.asyncio
async def test_concurrent_host_grants_create_one_binding(migrated_sync_url, seed):
    suffix = uuid.uuid4().hex
    person = AuthMeResponse(sub=f"concurrent-host-{suffix}", email=f"concurrent-host-{suffix}@example.com")
    engine = create_async_engine(normalize_database_url(async_db_url(migrated_sync_url)), pool_size=6)
    maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)

    async def enroll():
        async with maker() as session:
            result = await grant_held_roles(
                session, person, tenant_id=seed.tenant_id, requested=[HELD_HOST]
            )
            await session.commit()
            assert result.host
            return result.host.organization_id

    try:
        organizations = await asyncio.gather(*(enroll() for _ in range(6)))
        assert len(set(organizations)) == 1
        async with maker() as session:
            await set_current_tenant_id_guc(session, seed.tenant_id)
            members = (await session.execute(select(User).where(
                User.tenant_id == seed.tenant_id, User.email == person.email,
            ))).scalars().all()
            assert len(members) == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_host_authority_rolls_back_and_retry_reuses_owner_reservation(migrated_sync_url, seed):
    suffix = uuid.uuid4().hex
    person = AuthMeResponse(sub=f"rollback-{suffix}", email=f"rollback-{suffix}@example.com")
    engine = create_async_engine(normalize_database_url(async_db_url(migrated_sync_url)))
    maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    try:
        async with maker() as session:
            result = await grant_held_roles(session, person, requested=[HELD_HOST])
            assert result.host
            discarded = result.host.organization_id
            await session.rollback()
        async with maker() as session:
            await set_current_tenant_id_guc(session, seed.tenant_id)
            assert (await session.execute(select(User).where(
                User.tenant_id == seed.tenant_id, User.keycloak_sub == person.sub))).scalar_one_or_none() is None
            result = await grant_held_roles(session, person, requested=[HELD_HOST])
            assert result.host and result.host.organization_id == discarded
            await session.commit()
    finally:
        await engine.dispose()

@pytest.mark.asyncio
@pytest.mark.parametrize("username", ["admin", "admin@test.hyperme.sh", "renamed-account", None])
async def test_seeded_operator_gets_durable_scoped_membership(db_session, seed, monkeypatch, username):
    from user_service.identity_test_seed import provision_test_operator, EMAIL, ROLE
    from controlplane_api.config import settings
    from api.domain.operator.population import SEEDED_TEST_ADMIN_OPERATOR_CLAIMS
    from controlplane_api.exceptions import ForbiddenException
    monkeypatch.setenv("SPANOPTICON_TEST_OPERATOR_BOOTSTRAP", "1")
    issuer = "https://auth.test.hyperme.sh/realms/controlplane"
    monkeypatch.setattr(settings, "keycloak_issuer", issuer)
    claims = {"iss":issuer,"email":EMAIL,"email_verified":True,
              "preferred_username":username,"sub":"operator-seed-test", "realm_access":{"roles":["admin"]}}
    if username is None:
        claims.pop("preferred_username")
    # Isolate from other enrollment tests that deliberately create admin rows.
    from sqlalchemy import delete
    await db_session.execute(delete(User).where(User.tenant_id==seed.tenant_id, User.email==EMAIL))
    await provision_test_operator(claims,seed.tenant_id,db_session)
    await provision_test_operator(claims,seed.tenant_id,db_session)
    member = await db_session.scalar(select(User).where(User.tenant_id==seed.tenant_id,User.email==EMAIL))
    assert member.keycloak_sub == claims["sub"] and member.password is None
    grant = await authorize_tenant_switch(AuthMeResponse(sub=claims["sub"],email=EMAIL),seed.tenant_id,db_session)
    assert grant.role_name == ROLE
    assert set(grant.permissions) == set(SEEDED_TEST_ADMIN_OPERATOR_CLAIMS)
    with pytest.raises(ForbiddenException):
        await provision_test_operator({**claims,"sub":"different-account"},seed.tenant_id,db_session)
    member.is_active=False
    await db_session.flush()
    with pytest.raises(ForbiddenException):
        await provision_test_operator(claims,seed.tenant_id,db_session)

@pytest.mark.asyncio
async def test_seeded_host_role_attaches_existing_user_role(db_session, seed, monkeypatch):
    from user_service.identity_test_seed import (
        HOST_EMAIL, HOST_ROLE, TEST_ISSUER, ensure_seeded_host_role,
    )
    from controlplane_api.config import settings
    from sqlalchemy import delete
    monkeypatch.setattr(settings, "keycloak_issuer", TEST_ISSUER)
    subject = "leaser-seed-test"
    claims = {"iss": TEST_ISSUER, "email": HOST_EMAIL, "sub": subject}
    await db_session.execute(delete(User).where(
        User.tenant_id == seed.tenant_id, func.lower(User.email) == HOST_EMAIL))
    role = await db_session.scalar(select(Role).where(
        Role.tenant_id == seed.tenant_id, Role.name == HOST_ROLE))
    created_role = role is None
    if role is None:
        role = Role(id=uuid.uuid4(), tenant_id=seed.tenant_id, name=HOST_ROLE,
                    permissions=["user:view_only"])
        db_session.add(role)
        await db_session.flush()
    member = User(id=uuid.uuid4(), tenant_id=seed.tenant_id, email=HOST_EMAIL,
                  keycloak_sub=subject, first_name="Test", last_name="Host",
                  gender="unspecified", is_active=True, role_id=None, password=None)
    db_session.add(member)
    try:
        await db_session.flush()
        await ensure_seeded_host_role(claims, seed.tenant_id, db_session)
        await db_session.refresh(member)
        assert member.role_id == role.id
        grant = await authorize_tenant_switch(
            AuthMeResponse(sub=subject, email=HOST_EMAIL), seed.tenant_id, db_session)
        assert grant is not None and grant.role_name == HOST_ROLE
        await ensure_seeded_host_role(claims, seed.tenant_id, db_session)
        assert member.role_id == role.id
        custom = Role(id=uuid.uuid4(), tenant_id=seed.tenant_id, name="host-custom-seed",
                      permissions=[])
        db_session.add(custom)
        member.role_id = custom.id
        await db_session.flush()
        await ensure_seeded_host_role(claims, seed.tenant_id, db_session)
        assert member.role_id == custom.id
        member.role_id = None
        member.is_active = False
        await db_session.flush()
        assert await ensure_seeded_host_role(claims, seed.tenant_id, db_session) == "seeded_host_inactive"
        assert member.role_id is None
        assert await authorize_tenant_switch(
            AuthMeResponse(sub=subject, email=HOST_EMAIL), seed.tenant_id, db_session) is None
        member.is_active = True
        await db_session.flush()
        assert await ensure_seeded_host_role(
            {**claims, "sub": "other-person"}, seed.tenant_id, db_session,
        ) == "seeded_host_subject_mismatch"
        assert member.role_id is None
        if created_role:
            await db_session.delete(role)
            await db_session.flush()
            assert await ensure_seeded_host_role(claims, seed.tenant_id, db_session) is None
            await db_session.refresh(member)
            replacement = await db_session.scalar(select(Role).where(
                Role.tenant_id == seed.tenant_id, func.lower(Role.name) == HOST_ROLE))
            assert replacement is not None and member.role_id == replacement.id
            await db_session.delete(replacement)
            created_role = False
    finally:
        await db_session.execute(delete(User).where(User.id == member.id))
        await db_session.execute(delete(Role).where(Role.name == "host-custom-seed",
                                                    Role.tenant_id == seed.tenant_id))
        if created_role:
            await db_session.execute(delete(Role).where(Role.id == role.id))

@pytest.mark.asyncio
async def test_seeded_host_repairs_unresolved_platform_role_and_null_subject(
    db_session, seed, monkeypatch,
):
    from user_service.identity_test_seed import (
        HOST_EMAIL, HOST_ROLE, TEST_ISSUER, ensure_seeded_host_role,
    )
    from controlplane_api.config import settings
    from sqlalchemy import delete
    monkeypatch.setattr(settings, "keycloak_issuer", TEST_ISSUER)
    subject = "leaser-platform-role"
    claims = {"iss": TEST_ISSUER, "email": HOST_EMAIL, "sub": subject}
    await db_session.execute(delete(User).where(
        User.tenant_id == seed.tenant_id, func.lower(User.email) == HOST_EMAIL))
    platform = Role(id=uuid.uuid4(), tenant_id=None, name="platform-" + uuid.uuid4().hex,
                    permissions=["full:access"])
    db_session.add(platform)
    await db_session.flush()
    existing_user_role = await db_session.scalar(select(Role.id).where(
        Role.tenant_id == seed.tenant_id, func.lower(Role.name) == HOST_ROLE))
    member = User(id=uuid.uuid4(), tenant_id=seed.tenant_id, email=HOST_EMAIL,
                  keycloak_sub=None, first_name="Test", last_name="Host",
                  gender="unspecified", is_active=True, role_id=platform.id, password=None)
    db_session.add(member)
    duplicate = User(id=uuid.uuid4(), tenant_id=seed.tenant_id, email="Leaser@test.hyperme.sh",
                     keycloak_sub="someone-else", first_name="Other", last_name="Case",
                     gender="unspecified", is_active=True, role_id=None, password=None)
    db_session.add(duplicate)
    created_user_role = None
    try:
        await db_session.flush()
        assert await ensure_seeded_host_role(claims, seed.tenant_id, db_session) == "seeded_host_duplicate_membership"
        assert member.role_id == platform.id and member.keycloak_sub is None
        await db_session.delete(duplicate)
        await db_session.flush()
        assert await ensure_seeded_host_role(claims, seed.tenant_id, db_session) is None
        await db_session.refresh(member)
        tenant_role = await db_session.scalar(select(Role).where(
            Role.tenant_id == seed.tenant_id, func.lower(Role.name) == HOST_ROLE))
        assert tenant_role is not None and member.role_id == tenant_role.id
        assert member.keycloak_sub == subject
        assert set((await authorize_tenant_switch(
            AuthMeResponse(sub=subject, email=HOST_EMAIL), seed.tenant_id, db_session,
        )).permissions).isdisjoint({"full:access"})
        created_user_role = tenant_role
        member.role_id = tenant_role.id
        member.keycloak_sub = None
        await db_session.flush()
        assert await ensure_seeded_host_role(claims, seed.tenant_id, db_session) is None
        await db_session.refresh(member)
        assert member.role_id == tenant_role.id and member.keycloak_sub == subject
        from datetime import UTC, datetime
        member.deleted_at = datetime.now(UTC)
        await db_session.flush()
        assert await ensure_seeded_host_role(claims, seed.tenant_id, db_session) == "seeded_host_closed"
        await db_session.refresh(member)
        assert member.keycloak_sub == subject and member.role_id == tenant_role.id
        member.deleted_at = None
        await db_session.flush()
        await db_session.delete(member)
        await db_session.flush()
        member = None
        assert await ensure_seeded_host_role(claims, seed.tenant_id, db_session) == "seeded_host_missing"
    finally:
        if member is not None:
            await db_session.execute(delete(User).where(User.id == member.id))
        await db_session.execute(delete(User).where(User.id == duplicate.id))
        await db_session.execute(delete(Role).where(Role.id == platform.id))
        if created_user_role is not None and existing_user_role is None:
            referenced = await db_session.scalar(select(User.id).where(User.role_id == created_user_role.id))
            if referenced is None:
                await db_session.execute(delete(Role).where(Role.id == created_user_role.id))


@pytest.mark.asyncio
async def test_tenant_user_role_is_created_for_the_seeded_host_only(db_session):
    from user_service.identity_test_seed import _tenant_user_role
    from sqlalchemy import delete
    tenant_id = uuid.uuid4()
    await db_session.execute(text(
        "INSERT INTO tenants (id, name, is_active) VALUES (:id, :name, true)"
    ), {"id": tenant_id, "name": "seeded-host-role"})
    try:
        created = await _tenant_user_role(db_session, tenant_id)
        again = await _tenant_user_role(db_session, tenant_id)
        assert created is not None and again.id == created.id
        assert created.name == "user" and created.permissions == [] and created.tenant_id == tenant_id
    finally:
        await db_session.execute(delete(Role).where(Role.tenant_id == tenant_id))
        await db_session.execute(text("DELETE FROM tenants WHERE id=:id"), {"id": tenant_id})


@pytest.mark.asyncio
async def test_production_operator_membership_does_not_store_authority(db_session, seed, monkeypatch):
    from auth_service import operator_binding as binding
    monkeypatch.setattr(binding.settings, 'keycloak_issuer', binding.PRODUCTION_ISSUER)
    tenant, object_id = str(uuid.uuid4()), str(uuid.uuid4())
    monkeypatch.setenv('SPANOPTICON_OPERATOR_ENTRA_TENANT_ID', tenant)
    monkeypatch.setenv('SPANOPTICON_OPERATOR_ENTRA_OBJECT_ID', object_id)
    claims = dict(iss=binding.PRODUCTION_ISSUER, sub='entra-'+uuid.uuid4().hex,
                  email=uuid.uuid4().hex+'@fyberlabs.com', login_provider='microsoft',
                  entra_tenant_id=tenant, entra_object_id=object_id)
    await binding.provision(claims,seed.tenant_id,db_session)
    await binding.provision(claims,seed.tenant_id,db_session)
    grant=await authorize_tenant_switch(AuthMeResponse(sub=claims['sub'],email=claims['email']),seed.tenant_id,db_session)
    assert grant.role_name == binding.ROLE
    assert grant.permissions == ()
    assert 'operator:program' in binding.permissions(claims,seed.tenant_id,grant.role_name,grant.permissions)
    assert not binding.permissions({**claims,'login_provider':'google'},seed.tenant_id,grant.role_name,grant.permissions)
    assert await authorize_tenant_switch(AuthMeResponse(sub='other',email=claims['email']),seed.tenant_id,db_session) is None

@pytest.mark.asyncio
async def test_operator_bootstrap_preserves_existing_platform_identity(db_session, seed):
    from user_service.identity_test_seed import provision_operator, SEEDED_TEST_ADMIN_OPERATOR_CLAIMS
    from user_service.identity_tenant_switch import authorize_tenant_switch

    subject = f"operator-{uuid.uuid4()}"
    email = f"{subject}@example.com"
    platform = User(id=uuid.uuid4(), tenant_id=None, email=email,
                    keycloak_sub=subject, first_name="Existing", last_name="Account",
                    gender="other", is_active=True)
    db_session.add(platform)
    await db_session.flush()
    for _ in range(2):
        await provision_operator(
            {"sub": subject}, seed.tenant_id, email=email,
            role_name="test-network-operator", permissions=SEEDED_TEST_ADMIN_OPERATOR_CLAIMS,
            session=db_session,
        )
    rows = (await db_session.execute(
        select(User).where(User.keycloak_sub == subject)
    )).scalars().all()
    assert len(rows) == 2
    assert any(row.id == platform.id and row.tenant_id is None for row in rows)
    grant = await authorize_tenant_switch(
        AuthMeResponse(sub=subject, email=email), seed.tenant_id, session=db_session
    )
    assert grant is not None
    assert grant.role_name == "test-network-operator"
    assert set(grant.permissions) == set(SEEDED_TEST_ADMIN_OPERATOR_CLAIMS)


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign_role", [False, True])
async def test_switch_requires_a_resolved_target_role(db_session, seed, foreign_role):
    subject = "missing-role-" + uuid.uuid4().hex
    email = subject + "@example.com"
    role_id = None
    if foreign_role:
        role_id = uuid.uuid4()
        db_session.add(Role(id=role_id, tenant_id=None, name=subject,
                            permissions=["full:access"]))
        await db_session.flush()
    db_session.add(User(id=uuid.uuid4(), tenant_id=seed.tenant_id, keycloak_sub=subject,
        email=email, first_name="Role", last_name="Boundary", gender="unspecified",
        is_active=True, role_id=role_id))
    await db_session.flush()
    assert await authorize_tenant_switch(AuthMeResponse(sub=subject, email=email),
        seed.tenant_id, session=db_session) is None


@pytest.mark.asyncio
async def test_collision_cannot_switch_or_add_groups_to_another_subject(db_session, seed):
    email = uuid.uuid4().hex + "@example.com"
    victim = User(id=uuid.uuid4(), tenant_id=seed.tenant_id, keycloak_sub="victim-" + uuid.uuid4().hex,
        email=email, first_name="Bound", last_name="Owner", gender="unspecified", is_active=True)
    db_session.add(victim)
    await db_session.flush()
    caller = AuthMeResponse(sub="different-" + uuid.uuid4().hex, email=email)
    assert await authorize_tenant_switch(caller, seed.tenant_id, session=db_session) is None
    with pytest.raises(EnrollmentError, match="bound to another identity"):
        await grant_held_roles(db_session, caller, requested=[HELD_RENTER])
    assert victim.keycloak_sub != caller.sub
    assert await db_session.scalar(select(func.count()).select_from(UserGroupMembership).where(
        UserGroupMembership.user_id == victim.id)) == 0


@pytest.mark.asyncio
async def test_disabled_platform_manager_cannot_switch(db_session, seed):
    subject = "disabled-" + uuid.uuid4().hex
    role = Role(id=uuid.uuid4(), tenant_id=None, name=subject, permissions=["host:manage_tenants"])
    db_session.add(role)
    await db_session.flush()
    db_session.add(User(id=uuid.uuid4(), tenant_id=None, keycloak_sub=subject,
        email=subject + "@example.com", first_name="Disabled", last_name="Manager",
        gender="unspecified", is_active=False, role_id=role.id))
    await db_session.flush()
    assert await authorize_tenant_switch(AuthMeResponse(sub=subject, email=subject + "@example.com"),
        seed.tenant_id, session=db_session) is None


@pytest.mark.asyncio
async def test_switched_session_retains_target_renter_checkout_without_source_roles(db_session, seed, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from starlette.requests import Request
    from auth_service import routes
    from auth_service.schemas import SwitchTenantRequest
    from controlplane_api.config import settings
    from controlplane_identity.person_bind import can_checkout_from_me
    from controlplane_identity.security.tenant_session_jwt import try_decode_tenant_session_jwt

    subject = "checkout-" + uuid.uuid4().hex
    person = AuthMeResponse(sub=subject, email=subject + "@example.com", roles=["renter"])
    await grant_held_roles(db_session, person, requested=[HELD_RENTER])

    async def target_grant(user, tenant_id):
        return await authorize_tenant_switch(user, tenant_id, session=db_session)

    monkeypatch.setattr(routes, "authorize_tenant_switch", target_grant)
    monkeypatch.setattr(routes.outbox, "publish_auth_event", AsyncMock())
    monkeypatch.setattr(settings, "api_key_exchange_jwt_secret", "target-renter-regression-secret-at-least-32-chars")
    switched = await routes.auth_switch_tenant(
        SwitchTenantRequest(tenant_id=seed.tenant_id),
        Request({"type": "http", "headers": []}), person,
        {"sub": subject, "email": person.email, "spanopticon_auth": "tenant_session",
         "tenant_id": str(uuid.uuid4()), "azp": "controlplane-frontend",
         "realm_access": {"roles": ["renter", "admin"]}, "groups": ["source-only", "host"],
         "permissions": ["full:access"]},
    )
    claims = try_decode_tenant_session_jwt(switched.access_token)
    assert claims["realm_access"]["roles"] == ["user"]
    assert claims["groups"] == ["renter"]
    assert "full:access" not in claims["permissions"]
    assert can_checkout_from_me(claims["realm_access"]["roles"], claims["groups"])


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["host", "inactive", "closed", "unbound", "other-subject", "other-tenant", "renter"])
async def test_native_setup_uses_bound_active_host_group_without_inventing_tenant_role(
    db_session, seed, app, boundary, monkeypatch,
):
    from datetime import UTC, datetime
    from starlette.requests import Request
    from api.common.exceptions import ForbiddenException
    from api.infrastructure.security.tenant_session_jwt import try_decode_host_setup_session
    from auth_service.routes import host_setup_session
    from auth_service import identity_owner
    # The app fixture isolates route unit tests. This native case restores the
    # real command client, using identity_owner_http's actual owner router/SQL.
    monkeypatch.setattr(identity_owner, 'call', real_identity_owner_call)
    from auth_service.schemas import SwitchTenantRequest

    subject = "native-host-" + uuid.uuid4().hex
    person = AuthMeResponse(sub=subject, email=subject + "@example.com")
    member = User(id=uuid.uuid4(), tenant_id=seed.tenant_id, keycloak_sub=subject,
        email=person.email, first_name="Native", last_name="Host", gender="unspecified",
        is_active=True, role_id=None)
    db_session.add(member)
    await db_session.flush()
    granted = await grant_held_roles(db_session, person,
        requested=[HELD_RENTER if boundary == "renter" else HELD_HOST])
    assert not granted.refused
    assert member.role_id is None
    # The general tenant-switch contract must continue to reject incomplete roles.
    assert await authorize_tenant_switch(person, seed.tenant_id, session=db_session) is None
    tenant_id = seed.tenant_id
    if boundary == "inactive":
        member.is_active = False
    elif boundary == "closed":
        member.deleted_at = datetime.now(UTC)
    elif boundary == "unbound":
        member.keycloak_sub = None
    elif boundary == "other-subject":
        subject = "different-" + subject
    elif boundary == "other-tenant":
        tenant_id = uuid.uuid4()
    await db_session.flush()
    call = host_setup_session(SwitchTenantRequest(tenant_id=tenant_id),
        Request({"type": "http", "headers": []}),
        {"sub": subject, "email": person.email, "azp": "hypermesh-host-setup"})
    if boundary != "host":
        with pytest.raises(ForbiddenException):
            await call
    else:
        result = await call
        claims = try_decode_host_setup_session(result.access_token)
        assert claims["sub"] == subject
        assert claims["tenant_id"] == str(seed.tenant_id)
        assert claims["purpose"] == "host_setup"
        assert "permissions" not in claims
    assert member.role_id is None


@pytest.fixture(autouse=True)
def identity_owner_http(monkeypatch):
    """Real owner router and SQL implementation, using the native test transaction.

    Only the transport is in-process; auth still serializes and authenticates its
    command and the actual owner validates and executes it.
    """
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    from fastapi import FastAPI
    import httpx
    from auth_service import identity_owner
    from user_service.identity_api import router
    from api.infrastructure.persistence.db_session import get_db_session
    app = FastAPI(); app.include_router(router, prefix='/api/v1')
    class OwnerSession:
        def __init__(self, session): self.session = session
        def begin(self): return self.session.begin_nested()
        def __getattr__(self, name): return getattr(self.session, name)
    @asynccontextmanager
    async def maker():
        yield OwnerSession(get_db_session())
    app.state.session_maker = maker
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_URL', 'http://identity-owner.test')
    monkeypatch.setenv('AUTH_IDENTITY_OWNER_TOKEN', 'isolated-owner-test-token')
    factory = httpx.AsyncClient
    monkeypatch.setattr(identity_owner, 'httpx', SimpleNamespace(AsyncClient=lambda **kw: factory(
        transport=httpx.ASGITransport(app=app), **kw)))


@pytest.mark.parametrize('boundary', ['active','inactive','closed','unbound','other-subject','other-tenant','inactive-tenant','banned','lifted','foreign-ban','other-kind-ban'])
async def test_session_context_reads_real_owner_membership_and_durable_bans(db_session,seed,boundary):
    from datetime import UTC,datetime
    from auth_service.connect_session import current_member,MembershipRevoked
    from user_service.models import OperatorBan
    from controlplane_db.models import Tenant
    from api.domain.operator.bans import ban_book
    subject='session-member-'+uuid.uuid4().hex
    target=Tenant(id=uuid.uuid4(),name='context-target-'+uuid.uuid4().hex,is_active=True)
    member=User(id=uuid.uuid4(),tenant_id=target.id,keycloak_sub=subject,
        email=subject+'@example.invalid',first_name='Session',last_name='Member',gender='unspecified',is_active=True,role_id=None)
    other=Tenant(id=uuid.uuid4(),name='context-'+uuid.uuid4().hex,is_active=True)
    db_session.add_all([target,member,other]);await db_session.flush()
    tenant_id=target.id
    if boundary=='inactive':member.is_active=False
    elif boundary=='closed':member.deleted_at=datetime.now(UTC)
    elif boundary=='unbound':member.keycloak_sub=None
    elif boundary=='other-subject':subject='another-'+subject
    elif boundary=='other-tenant':tenant_id=other.id
    elif boundary=='inactive-tenant':
        from sqlalchemy import update
        await db_session.execute(update(Tenant).where(Tenant.id==target.id).values(is_active=False))
    if boundary in ('banned','lifted','foreign-ban','other-kind-ban'):
        db_session.add(OperatorBan(id=uuid.uuid4(),tenant_id=other.id if boundary=='foreign-ban' else target.id,
            subject_kind='group' if boundary=='other-kind-ban' else 'user',subject_id=member.id,
            reason='fixture',created_by='fixture',created_at=datetime.now(UTC),
            lifted_at=datetime.now(UTC) if boundary=='lifted' else None))
    await db_session.flush();ban_book().clear()
    try:
        if boundary in ('active','lifted','foreign-ban','other-kind-ban'):
            assert await current_member(tenant_id,subject)==str(member.id)
        else:
            with pytest.raises(MembershipRevoked):await current_member(tenant_id,subject)
    finally:ban_book().clear()


@pytest.mark.parametrize("scope_kind",["organization","network"])
async def test_scoped_session_uses_actual_owner_http_and_postgres(migrated_sync_url,app,http_client,monkeypatch,scope_kind):
    """Fresh local namespace only; no shared TEST identity or scope is touched."""
    import hashlib
    from pathlib import Path
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    from fastapi import FastAPI
    import httpx
    from sqlalchemy.engine import make_url
    from auth_service import scoped_session,network_session,deps
    from api.infrastructure.persistence.db_session import get_db_session
    from api.infrastructure.security.tenant_session_jwt import try_decode_tenant_session_jwt
    from user_service.scope_adapter import router
    from user_service.authority_migrate import install
    from importlib.resources import files
    from controlplane_events.owner_schema import migrate
    fixture=Path(__file__).with_name('fixtures')/'scope-owner'
    manifest=json.loads((fixture/'manifest.json').read_text())
    for name,digest in manifest['files'].items():assert hashlib.sha256((fixture/name).read_bytes()).hexdigest()==digest
    assert (fixture/'0002.sql').read_bytes()==files('user_service').joinpath('authority_schema.sql').read_bytes()
    name='local_auth_scope_'+uuid.uuid4().hex;reader=name+'_reader';password=uuid.uuid4().hex
    root=create_engine(migrated_sync_url)
    with root.begin() as db:
        for role in (name,reader):db.exec_driver_sql(f'CREATE ROLE "{role}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS')
        db.exec_driver_sql(f'CREATE SCHEMA "{name}" AUTHORIZATION "{name}"')
        for role in (name,reader):db.exec_driver_sql(f'ALTER ROLE "{role}" SET search_path TO "{name}"')
    owner=create_engine(make_url(migrated_sync_url).set(username=name,password=password))
    admin=create_engine(migrated_sync_url,connect_args={'options':'-csearch_path='+name})
    engine=create_async_engine(make_url(migrated_sync_url).set(drivername='postgresql+asyncpg',username=reader,password=password))
    maker=async_sessionmaker(engine,expire_on_commit=False)
    tenant,other,org,user=(uuid.uuid4() for _ in range(4));subject='local:scoped:'+uuid.uuid4().hex
    try:
        migrate(owner,revision='0001_owner_schema',ddl=(fixture/'0001.sql').read_text())
        install(owner)
        with admin.begin() as db:
            db.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{name}" TO "{reader}"')
            db.exec_driver_sql(f'GRANT SELECT ON ALL TABLES IN SCHEMA "{name}" TO "{reader}"')
            db.exec_driver_sql(f'GRANT UPDATE ON organization_memberships TO "{reader}"')
            db.execute(text("INSERT INTO authority_fixture_generation(generation,manifest_sha256,subjects_sha256,source_sha) VALUES('local-v1',:hash,:hash,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')"),{'hash':'a'*64})
            db.exec_driver_sql("INSERT INTO authority_networks VALUES('local-network',true)")
            db.execute(text('INSERT INTO tenants(id,name,is_active) VALUES(:id,:name,true)'),{'id':tenant,'name':str(tenant)})
            db.execute(text("INSERT INTO authority_tenants VALUES(:tenant,'local-network')"),{'tenant':tenant})
            db.execute(text("INSERT INTO organizations(id,tenant_id,legal_name) VALUES(:org,:tenant,'Local org')"),{'org':org,'tenant':tenant})
            db.execute(text("INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active) VALUES(:id,NULL,:sub,'local-scope@example.invalid','Local','Global','unspecified',true)"),{'id':user,'sub':subject})
            profile=uuid.uuid4()
            db.execute(text("INSERT INTO users(id,tenant_id,keycloak_sub,email,first_name,last_name,gender,is_active) VALUES(:id,:tenant,:sub,'local-scope@example.invalid','Local','Scope','unspecified',true)"),{'id':profile,'tenant':tenant,'sub':subject})
            db.execute(text("INSERT INTO organization_memberships VALUES(:tenant,:org,:user,'admin',false,true)"),{'tenant':tenant,'org':org,'user':profile})
            if scope_kind=='network':
                db.execute(text('DELETE FROM organization_memberships WHERE user_id=:profile'),{'profile':profile})
                db.execute(text('DELETE FROM users WHERE id=:profile'),{'profile':profile})
                db.execute(text("INSERT INTO authority_network_admins VALUES('local-network',:user,true)"),{'user':user})
        peer=FastAPI();peer.include_router(router,prefix='/api/v1');peer.state.session_maker=maker
        async def peer_db():
            async with maker() as db:
                async with db.begin():yield db
        peer.dependency_overrides[get_db_session]=peer_db
        factory=httpx.AsyncClient
        monkeypatch.setattr(scoped_session,'httpx',SimpleNamespace(HTTPError=httpx.HTTPError,AsyncClient=lambda **kw:factory(transport=httpx.ASGITransport(peer),**kw)))
        monkeypatch.setattr(network_session,'httpx',scoped_session.httpx)
        for key,value in {'USER_SCOPED_AUTHORITY_REQUIRED':'1','USER_TEST_FIXTURE_GENERATION':'local-v1','USER_SCOPE_GENERATION':'local-v1','AUTH_SCOPE_GENERATION':'local-v1','AUTH_SCOPE_MANIFEST_SHA256':'a'*64,'AUTH_SCOPE_AUTHORITY_URL':'https://local-scope-owner','AUTH_SCOPE_AUTHORITY_TOKEN':'local-scope-secret'}.items():monkeypatch.setenv(key,value)
        async def claims():return {'sub':subject,'azp':'controlplane-frontend','scope':'openid','realm_access':{'roles':['admin']}}
        app.dependency_overrides[deps.get_access_token_claims]=claims
        path='/auth/network-session' if scope_kind=='network' else '/auth/scoped-session'
        body={'tenant_id':str(tenant),**({'organization_id':str(org)} if scope_kind=='organization' else {})}
        result=await http_client.post(path,headers={'Authorization':'Bearer local-browser'},json=body)
        assert result.status_code==200,result.text
        signed=try_decode_tenant_session_jwt(result.json()['access_token'])
        assert signed['scope_kind']==scope_kind
        if scope_kind=='organization':
            assert signed['organization_id']==str(org) and signed['realm_access']['roles']==['org:admin']
            assert signed['permissions']==[]
            other_body={**body,'organization_id':str(other)}
        else:
            assert signed['organization_id'] is None and signed['realm_access']['roles']==['network:admin']
            assert set(signed['permissions'])=={'operator:console','operator:support','operator:program','operator:resolve'}
            other_body={'tenant_id':str(other)}
        denied=await http_client.post(path,headers={'Authorization':'Bearer local-browser'},json=other_body)
        assert denied.status_code==403
        with admin.begin() as db:
            if scope_kind=='organization':db.execute(text('UPDATE organization_memberships SET enabled=false WHERE user_id=:user'),{'user':profile})
            else:db.execute(text('UPDATE authority_network_admins SET enabled=false WHERE user_id=:user'),{'user':user})
        denied=await http_client.post(path,headers={'Authorization':'Bearer local-browser'},json=body)
        assert denied.status_code==403
    finally:
        app.dependency_overrides.pop(deps.get_access_token_claims,None)
        await engine.dispose();owner.dispose();admin.dispose()
        with root.begin() as db:
            db.exec_driver_sql(f'DROP SCHEMA "{name}" CASCADE')
            for role in (reader,name):db.exec_driver_sql(f'DROP OWNED BY "{role}"');db.exec_driver_sql(f'DROP ROLE "{role}"')
        root.dispose()
