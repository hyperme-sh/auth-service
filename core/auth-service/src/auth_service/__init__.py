"""Auth microservice: Keycloak OIDC routes, JWT / introspection, Kafka auth events.

Import the ASGI app as ``from auth_service.app import app`` (avoids import cycles).
"""

from auth_service.deps import (
    CurrentTenant,
    CurrentUser,
    get_current_tenant,
    get_current_user,
)

__all__ = [
    "CurrentTenant",
    "CurrentUser",
    "get_current_tenant",
    "get_current_user",
]
