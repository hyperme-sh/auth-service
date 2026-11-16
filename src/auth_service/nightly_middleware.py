"""Admit scoped Auth requests before native dispatch; acknowledge after DB middleware."""
import json
from auth_service import nightly_state as state
from auth_service.nightly_runtime import admission
from controlplane_identity.nightly import admitted_run


class NightlyMiddleware:
    def __init__(self, app): self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['path'] == '/auth/nightly-run/v1/command':
            return await self.app(scope, receive, send)
        app = scope['app']; config = app.state.nightly_config
        if config is None: return await self.app(scope, receive, send)
        headers = scope.get('headers', [])
        grants = [v for k, v in headers if k.lower() == b'x-nightly-run-grant']
        if not grants: return await self.app(scope, receive, send)
        binding = None; token = None; messages = []; size = 0
        async def buffer(message):
            nonlocal size
            if message['type'] == 'http.response.body':
                size += len(message.get('body', b'')); state.require(size <= 8 * 1024 * 1024)
            messages.append(message)
        try:
            state.require(len(grants) == 1 and scope['path'].startswith('/auth/'))
            # No unrelated enrollment, SIWE or host mutation is admitted by a browser grant.
            state.require((scope['method'], scope['path']) in {('GET', '/auth/me'), ('GET', '/auth/startup/identity'), ('POST', '/auth/switch-tenant'), ('POST', '/auth/scoped-session')}
                          or scope['path'].startswith('/auth/sea-device-link/v1/sessions/'))
            store = app.state.nightly_store; state.require(store is not None)
            binding = await store.command(dict(version=1, owner='auth', action='admit', grant=grants[0].decode('ascii')))
            token = admission.set(binding)
            with admitted_run(binding):
                await self.app(scope, receive, buffer)
            starts = [m for m in messages if m['type'] == 'http.response.start']
            state.require(len(starts) == 1 and 200 <= starts[0]['status'] < 400
                          and messages[-1]['type'] == 'http.response.body' and not messages[-1].get('more_body', False))
            await store.command(dict(version=1, owner='auth', action='complete', run=binding['run'],
                                     generation=binding['generation'], operation=binding['operation']))
            for message in messages: await send(message)
        except Exception:
            body = json.dumps({'error': 'nightly-run-refused'}).encode()
            await send(dict(type='http.response.start', status=409, headers=[(b'content-type', b'application/json'), (b'cache-control', b'private, no-store')]))
            await send(dict(type='http.response.body', body=body))
        finally:
            if binding is not None: binding['_closed'] = True
            if token is not None: admission.reset(token)
