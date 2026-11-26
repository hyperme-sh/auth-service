"""Give handlers a request session and scope its first database operation."""
import uuid

from api.core.container import get_tenant_service
from api.core.exceptions import TenantNotFoundException
from api.infrastructure.persistence.db_session import reset_db_session, set_db_session
from api.interfaces.middlewares.database_middleware import get_tenant_host
from controlplane_api.utils import get_logger, is_subdomain, is_tenancy_enabled
from sqlalchemy import event, text
from starlette.middleware.base import BaseHTTPMiddleware

logger = get_logger(__name__)
HEALTH_PATHS = {"/api/v1/health", "/api/v1/health/"}
SET_TENANT = text("SELECT set_config('app.current_tenant_id', :tenant, true)")


async def resolve_tenant(request, session):
    if not is_tenancy_enabled():
        return None
    host = get_tenant_host(request)
    if host:
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
            # The host lookup is read-only. Release its connection before
            # invoking any handler that needs the shared pool.
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
            except Exception:
                await session.rollback()
                raise
            finally:
                reset_db_session(token)
