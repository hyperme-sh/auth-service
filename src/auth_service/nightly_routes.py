"""Authenticated server-to-server owner commands; never browser supplied proof."""
import asyncio
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from auth_service.nightly_runtime import authenticate
from auth_service import nightly_state as state

router = APIRouter()


@router.post('/auth/nightly-run/v1/command', include_in_schema=False)
async def command(request: Request):
    try:
        async with asyncio.timeout(12):
            state.require(request.headers.get('content-type', '').split(';')[0] == 'application/json'
                          and not request.headers.get('content-encoding'))
            raw = bytearray()
            async for part in request.stream():
                raw.extend(part); state.require(len(raw) <= 16384)
            config = request.app.state.nightly_config
            value = authenticate(config, bytes(raw), request.headers.get('x-nightly-owner-signature'))
            store = request.app.state.nightly_store; state.require(store is not None)
            result = await store.command(value)
            return JSONResponse(result, headers={'Cache-Control': 'private, no-store'})
    except Exception:
        return JSONResponse({'error': 'nightly-run-refused'}, status_code=409,
                            headers={'Cache-Control': 'private, no-store'})
