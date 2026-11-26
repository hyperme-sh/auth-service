"""Give handlers a request session and scope its first database operation."""
import os
import uuid

import httpx

from api.core.container import get_tenant_service
from api.core.exceptions import TenantNotFoundException
from api.infrastructure.persistence.db_session import reset_db_session, set_db_session
from api.interfaces.middlewares.database_middleware import get_tenant_host
from controlplane_api.utils import get_logger, is_subdomain, is_tenancy_enabled
from sqlalchemy import event, text
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = get_logger(__name__)
HEALTH_PATHS = {"/api/v1/health", "/api/v1/health/"}
EXPLICIT_TENANT_PATHS = {"/auth/scoped-session", "/auth/network-session"}
SET_TENANT = text("SELECT set_config('app.current_tenant_id', :tenant, true)")


class TenantOwnerUnavailable(Exception):
    """The configured tenant owner could not resolve the request."""


async def resolve_owner_tenant(host, url, token):
    if not url or not token:
        raise TenantOwnerUnavailable
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
            response = await client.get(
                url.rstrip("/") + "/api/v1/internal/identity/domain",
                params={"host": host},
                headers={"Authorization": "Bearer " + token},
            )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return uuid.UUID(response.json()["tenant_id"])
    except (httpx.HTTPError, KeyError, ValueError, TypeError, AttributeError) as error:
        raise TenantOwnerUnavailable from error


async def resolve_tenant(request, session):
    if not is_tenancy_enabled():
        return None
    host = None if request.url.path.rstrip("/") in EXPLICIT_TENANT_PATHS else get_tenant_host(request)
    if host:
        owner_url = os.environ.get("USER_SERVICE_URL", "")
        owner_token = os.environ.get("TENANT_OWNER_TOKEN", "")
        if owner_url or owner_token:
            tenant = await resolve_owner_tenant(host, owner_url, owner_token)
            if tenant is not None:
                request.state.frontend_host = host
                return tenant
        else:
            tenants = get_tenant_service()
            try:
                if is_subdomain(host):
                    tenant = await tenants.find_by_subdomain(host)
                else:
                    tenant = await tenants.find_by_custom_domain(host)
                request.state.frontend_host = host
                return tenant.id
            except TenantNotFoundException as error:
                logger.warning("Tenant resolve failed for host %r: %s", host, error)
            finally:
                # Release the legacy lookup's connection before handler work.
                await session.rollback()

    tenant = request.headers.get("X-Tenant-ID") or request.query_params.get("tenant_id")
    if tenant:
        try:
            return uuid.UUID(tenant)
        except ValueError:
            logger.warning("Invalid tenant id header/param: %r", tenant)
    return None


class AuthTransactionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        async with request.app.state.session_maker() as session:
            token = set_db_session(session)
            tenant = None

            def scope_transaction(_session, transaction, connection):
                if not transaction.nested:
                    connection.execute(SET_TENANT, {"tenant": str(tenant) if tenant else ""})

            event.listen(session.sync_session, "after_begin", scope_transaction)
            try:
                tenant = await resolve_tenant(request, session)
                request.state.tenant_id = tenant
                if request.url.path in HEALTH_PATHS:
                    # Readiness still checks the owner database through this pool.
                    await session.connection()
                response = await call_next(request)
                if response.status_code >= 400:
                    await session.rollback()
                else:
                    await session.commit()
                return response
            except TenantOwnerUnavailable:
                await session.rollback()
                logger.warning("Configured tenant owner lookup unavailable")
                return JSONResponse({"detail": "Tenant owner unavailable"}, status_code=503)
            except Exception:
                await session.rollback()
                raise
            finally:
                reset_db_session(token)
