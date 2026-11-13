from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from controlplane_api.exceptions import ForbiddenException, UnauthorizedException
from controlplane_api.logging import configure_logging
from controlplane_api.utils import get_logger
from controlplane_api.config import settings
from api.infrastructure.persistence.db_session import configure_session_maker
from controlplane_api.service_cors import add_optional_service_cors
from controlplane_api.health import router as health_router
from controlplane_api.version import router as version_router
from auth_service.transaction import AuthTransactionMiddleware
from controlplane_db.session import normalize_database_url

from auth_service.routes import router as auth_router
from auth_service.smoke_oidc import assert_smoke_oidc_plane

logger = get_logger(__name__)


def create_app(
    *,
    test_event_sink: list | None = None,
    enable_db_middleware: bool = True,
) -> FastAPI:
    @asynccontextmanager
    async def service_lifespan(app: FastAPI):
        configure_logging()
        assert_smoke_oidc_plane()
        engine = None
        if enable_db_middleware:
            engine = create_async_engine(normalize_database_url(settings.database_url))
            maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
            configure_session_maker(maker)
            app.state.async_engine = engine

        try:
            yield
        finally:
            if engine is not None:
                await engine.dispose()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from auth_service.siwe_nonces import nonce_runtime

        async with nonce_runtime() as store:
            app.state.siwe_nonce_store = store
            try:
                async with service_lifespan(app):
                    yield
            finally:
                app.state.siwe_nonce_store = None

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
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(version_router)
    app.include_router(auth_router, prefix="/auth")
    if enable_db_middleware:
        logger.info("Auth service middleware: DbSessionMiddleware (RLS GUC)")
    add_optional_service_cors(app, env_var="AUTH_SERVICE_CORS_ORIGINS")
    from controlplane_api.metrics import install_http_metrics

    install_http_metrics(app)
    return app


app = create_app()
