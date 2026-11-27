"""Service-local probes for Auth deployments."""

import asyncio

from fastapi import APIRouter, Request, Response
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

LIVENESS_PATH = "/api/v1/health/live"
READINESS_PATH = "/api/v1/health/ready"
PROBE_PATHS = {LIVENESS_PATH, READINESS_PATH}

router = APIRouter(include_in_schema=False)


@router.get(LIVENESS_PATH)
async def live() -> Response:
    return Response(status_code=200)


@router.get(READINESS_PATH)
async def ready(request: Request) -> Response:
    engine = getattr(request.app.state, "async_engine", None)
    if engine is None:
        return Response(status_code=503)
    try:
        async with asyncio.timeout(2), engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except (OSError, SQLAlchemyError, TimeoutError):
        return Response(status_code=503)
    return Response(status_code=200)
