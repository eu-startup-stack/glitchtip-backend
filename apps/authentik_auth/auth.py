"""
django-ninja auth class for Authentik-proxied requests.

The middleware already populates ``request.authentik_auth`` with the
resolved ``Auth`` object — this class is a thin shim that returns it
during django-ninja's auth dispatch so the OpenAPI surface still
shows an HTTP-bearer-like scheme we can document. When the feature is
off (or the middleware didn't authenticate the request) the class
declares no auth and the rest of the chain (``TokenAuth``,
``SessionAuth``) takes over.
"""

from typing import Any

from django.conf import settings
from django.http import HttpRequest
from ninja.security import HttpBearer


class AuthentikHeaderAuth(HttpBearer):
    """Return the auth object stashed on the request by the middleware."""

    openapi_scheme = "authentik"

    async def __call__(self, request: HttpRequest) -> Any | None:
        # ``__call__`` MUST be a coroutine: ``AuthentikHeaderAuth`` declares
        # ``async def authenticate`` (kept below to satisfy ``HttpBearer``'s
        # abstract base), so ``AuthBase.__init__`` sets ``self.is_async = True``
        # via ``is_async_callable``. ninja's ``AsyncOperation._run_authentication``
        # then does ``cor = callback(request); result = await cor`` — i.e. it
        # unconditionally awaits whatever ``__call__`` returns. A sync ``__call__``
        # that returns the bare ``Auth`` dataclass tripped this contract and
        # raised ``TypeError: object Auth can't be used in 'await' expression``,
        # which ``ninja`` routed through ``on_exception`` and surfaced as a 500
        # on every Authentik-authenticated request to a protected route.
        if not getattr(settings, "AUTHENTIK_PROXY_AUTH_ENABLED", False):
            return None
        return getattr(request, "authentik_auth", None)

    async def authenticate(self, request: HttpRequest, token: str) -> Any | None:
        # The middleware already produced the Auth object via ``__call__``
        # before this class is reached, so ``authenticate`` would only run
        # if ``HttpBearer.__call__`` were the entry point and tried to pull
        # a token from the ``Authorization`` header — which it doesn't for
        # Authentik requests. Kept async purely so ``is_async_callable`` keeps
        # ``self.is_async = True`` and ninja continues to await ``__call__``.
        return None
