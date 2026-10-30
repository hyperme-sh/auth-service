"""Platform role seed stays on tenant_id NULL and is safe to run twice.

A tenant-scoped "user" role is a different row. Looking that name up
without a tenant filter raises MultipleResultsFound and stops the edge.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.domain.enum.permission import Permission
from api.infrastructure.persistence.db_session import reset_db_session, set_db_session
from api.infrastructure.persistence.repositories.role_repository_impl import RoleRepository
from api.infrastructure.persistence.seeder import seed_platform_roles
from api.infrastructure.persistence.tenant_membership import MARKETPLACE_TENANT_ID
from controlplane_db.models import Group, Role
from controlplane_db.session import normalize_database_url
from panopticon_tests.fixtures.postgres import (
    async_db_url,
    normalize_sync_sqlalchemy_url,
    run_alembic_upgrade,
)


@pytest.fixture(scope="module")
def require_docker() -> None:
    if os.environ.get("SKIP_TESTCONTAINERS", "").lower() in ("1", "true", "yes"):
        pytest.skip("SKIP_TESTCONTAINERS is set")
    try:
        import docker

        docker.from_env().ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Docker not available for testcontainers: {exc}")


@pytest.fixture(scope="module")
def postgres_url(require_docker: None) -> str:
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16-alpine") as pg:
        url = normalize_sync_sqlalchemy_url(pg.get_connection_url())
        run_alembic_upgrade(url)
        yield url


async def _seed_once(maker) -> None:
    async with maker() as session:
        token = set_db_session(session)
        try:
            await session.execute(text("SELECT set_config('app.current_tenant_id', '', true)"))
            await seed_platform_roles(RoleRepository())
            await session.commit()
        finally:
            reset_db_session(token)


@pytest.mark.asyncio
async def test_seed_twice_and_concurrent_with_tenant_user_role(postgres_url: str) -> None:
    tenant_role_id = uuid.uuid4()
    group_id = uuid.uuid4()
    eng = create_engine(postgres_url)
    with eng.begin() as cx:
        cx.execute(
            text(
                """
                INSERT INTO roles (id, tenant_id, name, permissions, created_at, updated_at)
                VALUES (
                    :id, :tid, 'user', '["tenant"]'::jsonb,
                    '2026-09-25T14:06:08Z', '2026-09-25T14:06:08Z'
                )
                """
            ),
            {"id": tenant_role_id, "tid": MARKETPLACE_TENANT_ID},
        )
        cx.execute(
            text(
                """
                INSERT INTO groups (id, tenant_id, name, role_id)
                VALUES (:id, :tid, 'renter', :role)
                """
            ),
            {"id": group_id, "tid": MARKETPLACE_TENANT_ID, "role": tenant_role_id},
        )

    db_url = async_db_url(postgres_url)
    engine = create_async_engine(
        normalize_database_url(db_url),
        pool_size=8,
        max_overflow=8,
    )
    maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    try:
        await asyncio.gather(*[_seed_once(maker) for _ in range(8)])

        async with maker() as session:
            token = set_db_session(session)
            try:
                platform = (
                    await session.execute(
                        select(Role.name, Role.id, Role.permissions).where(Role.tenant_id.is_(None))
                    )
                ).all()
                counts = (
                    await session.execute(
                        select(func.lower(Role.name), func.count())
                        .where(Role.tenant_id.is_(None))
                        .group_by(func.lower(Role.name))
                    )
                ).all()
                tenant_row = (
                    await session.execute(
                        select(Role.tenant_id, Role.name).where(Role.id == tenant_role_id)
                    )
                ).one()
                pointed = (
                    await session.execute(
                        select(Group.role_id).where(Group.id == group_id)
                    )
                ).scalar_one()
            finally:
                reset_db_session(token)

        assert {name for name, _count in counts} == {
            "admin",
            "user",
            "guest",
            "billing_manager",
        }
        assert all(count == 1 for _name, count in counts)
        by_name = {row[0]: row for row in platform}
        assert Permission.HOST_MANAGE_TENANTS.value in (by_name["admin"][2] or [])
        first_ids = {row[0]: row[1] for row in platform}
        assert tenant_row[0] == MARKETPLACE_TENANT_ID
        assert tenant_row[1] == "user"
        assert pointed == tenant_role_id

        await _seed_once(maker)
        async with maker() as session:
            token = set_db_session(session)
            try:
                again = (
                    await session.execute(
                        select(Role.name, Role.id).where(Role.tenant_id.is_(None))
                    )
                ).all()
                still_pointed = (
                    await session.execute(
                        select(Group.role_id).where(Group.id == group_id)
                    )
                ).scalar_one()
            finally:
                reset_db_session(token)
        assert {row[0]: row[1] for row in again} == first_ids
        assert still_pointed == tenant_role_id
    finally:
        await engine.dispose()
