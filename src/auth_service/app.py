from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import async_sessionmaker

from controlplane_api.exceptions import ForbiddenException, UnauthorizedException
from controlplane_api.logging import configure_logging
from controlplane_api.utils import get_logger
from controlplane_api.config import settings
from api.infrastructure.persistence.db_session import configure_session_maker
from controlplane_api.service_cors import add_optional_service_cors
from controlplane_api.health import router as health_router
from controlplane_api.version import router as version_router
from auth_service.transaction import AuthTransactionMiddleware
from auth_service.database import runtime_engines
from auth_service.health import router as local_health_router

from auth_service.routes import router as auth_router
from auth_service.smoke_oidc import assert_smoke_oidc_plane

logger = get_logger(__name__)


def create_app(
    *,
    test_event_sink: list | None = None,
    enable_db_middleware: bool = True,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from auth_service.nightly_runtime import configuration
        from auth_service.nightly_store import PostgresNightlyStore
        from auth_service.pairing_runtime import pairing_runtime, read_scopes
        from auth_service.siwe_nonces import nonce_database_url, nonce_runtime

        configure_logging()
        assert_smoke_oidc_plane()
        scopes = read_scopes()
        owner_url = settings.database_url if enable_db_middleware or scopes else None
        async with runtime_engines(owner_url, nonce_database_url()) as (engine, nonce_engine):
            if enable_db_middleware:
                maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
                configure_session_maker(maker)
                app.state.session_maker = maker
                app.state.async_engine = engine
                app.state.nightly_config = configuration()
                if app.state.nightly_config is not None:
                    from controlplane_identity.nightly import configure_subjects
                    configure_subjects([s["subject"] for s in app.state.nightly_config["scopes"].values()])
                    app.state.nightly_store = PostgresNightlyStore(engine, app.state.nightly_config["scopes"])

            async with nonce_runtime(nonce_engine) as nonce_store, pairing_runtime(engine, scopes) as pairing_store:
                app.state.pairing_scopes = scopes
                app.state.pairing_store = pairing_store
                app.state.siwe_nonce_store = nonce_store
                try:
                    yield
                finally:
                    app.state.siwe_nonce_store = None
                    app.state.pairing_store = None

    app = FastAPI(
        lifespan=lifespan,
        title="spanopticon Auth Service",
        description="Keycloak OIDC: login, callback, refresh, JWT validation, RLS session middleware.",
        version="0.2.0",
    )

    @app.exception_handler(UnauthorizedException)
    async def _unauthorized(_: Request, ex: UnauthorizedException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": ex.message},
        )

    @app.exception_handler(ForbiddenException)
    async def _forbidden(_: Request, ex: ForbiddenException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": ex.message},
        )

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema
        from fastapi.openapi.utils import get_openapi

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description or "",
            routes=app.routes,
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {})[
            "BearerAuth"
        ] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Keycloak access token",
        }
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi

    if enable_db_middleware:
        app.add_middleware(AuthTransactionMiddleware)
    from auth_service.nightly_middleware import NightlyMiddleware
    from auth_service.nightly_routes import router as nightly_router
    app.state.nightly_config = None
    app.state.nightly_store = None
    app.add_middleware(NightlyMiddleware)
    app.include_router(nightly_router)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(local_health_router)
    app.include_router(version_router)
    app.include_router(auth_router, prefix="/auth")
    from auth_service.first_oidc_routes import router as first_oidc_router
    app.state.first_oidc_slots = asyncio.Semaphore(2)
    app.include_router(first_oidc_router)
    from auth_service.first_genesis_routes import router as first_genesis_router
    app.state.first_genesis_slots = asyncio.Semaphore(2)
    app.include_router(first_genesis_router)
    from auth_service.linked_oidc_routes import router as linked_oidc_router
    app.state.linked_oidc_slots = asyncio.Semaphore(4)
    app.include_router(linked_oidc_router)
    from auth_service.pairing_routes import router as pairing_router
    app.state.pairing_slots = asyncio.Semaphore(8)
    app.state.pairing_store = None
    app.state.pairing_scopes = ()
    app.include_router(pairing_router)
    if enable_db_middleware:
        logger.info("Auth service middleware: DbSessionMiddleware (RLS GUC)")
    add_optional_service_cors(app, env_var="AUTH_SERVICE_CORS_ORIGINS")
    from controlplane_api.metrics import install_http_metrics

    install_http_metrics(app)
    return app


app = create_app()
