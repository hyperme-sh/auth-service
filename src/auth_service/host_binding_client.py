"""Auth calls the Hypermesh owner; no product persistence imports or fallback."""
import uuid
from dataclasses import dataclass

import httpx
from fastapi import HTTPException
from controlplane_api.config import settings


@dataclass(frozen=True)
class HttpHostBindingClient:
    base_url: str
    token: str
    transport: httpx.AsyncBaseTransport | None = None

    async def resolve(self, tenant_id: uuid.UUID, subject: str) -> uuid.UUID:
        if not self.base_url or len(self.token.strip()) < 32:
            raise HTTPException(503, "Host organization owner is not configured")
        try:
            async with httpx.AsyncClient(timeout=10, transport=self.transport) as client:
                response = await client.post(
                    self.base_url.rstrip("/") + "/api/v1/hypermesh/internal/host-organization",
                    headers={"X-Tenant-ID": str(tenant_id), "X-Internal-Token": self.token},
                    json={"tenant_id": str(tenant_id), "subject": subject})
                response.raise_for_status()
                data = response.json()
                if data.get("tenant_id") != str(tenant_id) or data.get("subject") != subject:
                    raise ValueError("Owner identity mismatch")
                return uuid.UUID(data["organization_id"])
        except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(503, "Host organization owner requires reconciliation") from None


def host_binding_client() -> HttpHostBindingClient:
    return HttpHostBindingClient(settings.auth_host_binding_url.strip(),
                                 settings.host_binding_internal_token.strip())
