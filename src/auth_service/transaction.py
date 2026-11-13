"""Keep the shared request-session contract while rolling back error responses."""
from api.interfaces.middlewares.database_middleware import DbSessionMiddleware


class _RejectedResponse(Exception):
    def __init__(self, response):
        self.response = response


class AuthTransactionMiddleware(DbSessionMiddleware):
    async def dispatch(self, request, call_next):
        async def checked(request):
            response = await call_next(request)
            if response.status_code >= 400:
                raise _RejectedResponse(response)
            return response
        try:
            return await super().dispatch(request, checked)
        except _RejectedResponse as rejected:
            return rejected.response
