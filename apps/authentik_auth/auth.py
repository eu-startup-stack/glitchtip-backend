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

from typing import Any, Optional

from django.conf import settings
from django.http import HttpRequest
from ninja.security import HttpBearer


class AuthentikHeaderAuth(HttpBearer):
    """Return the auth object stashed on the request by the middleware."""

    openapi_scheme = "authentik"

    def __call__(self, request: HttpRequest) -> Optional[Any]:
        if not getattr(settings, "AUTHENTIK_PROXY_AUTH_ENABLED", False):
            return None
        return getattr(request, "authentik_auth", None)

    async def authenticate(self, request: HttpRequest, token: str) -> Optional[Any]:
        # The middleware already produced the Auth object via __call__.
        # This method exists only to satisfy HttpBearer's abstract base
        # and is never invoked in practice.
        return None
