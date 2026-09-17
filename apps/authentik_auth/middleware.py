"""
ASGI/Django middleware that turns Authentik proxy headers into a
locally-authenticated request.

The middleware is gated on a master toggle so it is a complete no-op in
deployments that do not run behind Authentik. When enabled, it:

1. Accepts ``X-authentik-*`` headers ONLY from configured trusted proxy
   IPs (the Authentik outpost). Headers from anywhere else are stripped
   so a direct client cannot impersonate another user.
2. JIT-provisions a local ``User`` (and a verified allauth
   ``EmailAddress``) the first time we see their email.
3. Mirrors the resolved role onto every non-deleted organization's
   ``OrganizationUser`` for that user, with a per-groups-hash cache to
   keep the hot path cheap.
4. Sets ``request.user`` and ``request.authentik_auth`` so the rest of
   Django and the django-ninja auth chain treats the request as a
   logged-in session user.

Ingest endpoints are unaffected: the ingest ASGI dispatcher routes
those paths to a minimal-middleware app before this middleware runs.
"""

import ipaddress
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse

from glitchtip.api.authentication import Auth

from .mapping import parse_groups, resolve_role
from .provisioning import (
    get_or_create_user,
    groups_hash,
    sync_org_memberships,
)

# Paths that must always pass through unauthenticated so probes still
# work for clients that haven't (and shouldn't) carry Authentik headers.
_HEALTH_EXEMPT_PATHS = frozenset({"/_health/", "/api/0/internal/health"})

_TRUSTED_PROXY_CACHE: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}


def _is_trusted_proxy(peer: str) -> bool:
    """Return True when ``peer`` is in ``AUTHENTIK_TRUSTED_PROXIES``.

    Each entry is either a literal IP ("10.0.0.1") or a CIDR
    ("10.0.0.0/24"). Unparseable entries are ignored — the deploy would
    already be broken at startup if any entry were syntactically
    invalid, so we don't crash the request path for a config typo.
    """
    if not peer:
        return False
    trusted: list[str] = getattr(settings, "AUTHENTIK_TRUSTED_PROXIES", []) or []
    if not trusted:
        return False
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for entry in trusted:
        if not entry:
            continue
        if "/" in entry:
            try:
                network = _TRUSTED_PROXY_CACHE.get(entry)
                if network is None:
                    network = ipaddress.ip_network(entry, strict=False)
                    _TRUSTED_PROXY_CACHE[entry] = network
                if peer_ip in network:
                    return True
            except ValueError:
                continue
        else:
            try:
                if peer_ip == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
    return False


def _strip_authentik_headers(request: HttpRequest) -> None:
    """Remove every ``X-authentik-*`` header from ``request.META``."""
    for key in list(request.META):
        if key.startswith("HTTP_X_AUTHENTIK_"):
            del request.META[key]


class AuthentikProxyMiddleware:
    """Authenticate requests via Authentik's forwarded headers."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    async def __call__(self, request: HttpRequest) -> HttpResponse:
        if not getattr(settings, "AUTHENTIK_PROXY_AUTH_ENABLED", False):
            return await self.get_response(request)

        peer = request.META.get("REMOTE_ADDR", "")
        if not _is_trusted_proxy(peer):
            _strip_authentik_headers(request)
            return await self.get_response(request)

        email = (request.META.get("HTTP_X_AUTHENTIK_EMAIL") or "").strip()
        if not email:
            # Proxy didn't auth this request (e.g. direct internal call
            # to a non-auth path). Pass through unchanged; downstream
            # auth decides whether to allow it.
            return await self.get_response(request)

        name = (request.META.get("HTTP_X_AUTHENTIK_NAME") or "").strip()
        groups = parse_groups(request.META.get("HTTP_X_AUTHENTIK_GROUPS", ""))
        role = resolve_role(groups, settings.AUTHENTIK_GROUP_PREFIX)

        if role is None:
            # No glitchtip- role -> deny. Health probes are the only
            # exemption: they pass through unauthenticated (no user is
            # provisioned, no auth stashed) so a probe can't mint users.
            if request.path not in _HEALTH_EXEMPT_PATHS:
                return HttpResponse(
                    "Access denied: no glitchtip role assigned.",
                    status=403,
                    content_type="text/plain",
                )
            return await self.get_response(request)

        user = await get_or_create_user(email, name)
        await sync_org_memberships(user, role, groups_hash(groups))

        request.user = user
        request.authentik_auth = Auth(user.id, "session")
        # ninja's SessionAuth (glitchtip/api/authentication.py) extends
        # ninja.security.APIKeyCookie, which runs Django's CSRF check
        # BEFORE AuthentikHeaderAuth is ever reached in the auth chain
        # (glitchtip/api/api.py: [TokenAuth, SessionAuth,
        # AuthentikHeaderAuth]). This middleware deliberately never
        # writes a Django session, so there is no ambient session
        # cookie for a forged cross-site request to ride on -- the
        # trust boundary for this request is the _is_trusted_proxy
        # check above, not a CSRF token. Left alone, every Authentik
        # SSO POST/PUT/DELETE without a Django CSRF token 403s in
        # production, purely because of auth-chain ordering, not
        # because the request is actually forgeable the way session
        # CSRF protects against.
        #
        # _ninja_csrf_exempt is ninja's own documented escape hatch
        # (ninja.security.apikey.APIKeyBase._get_key checks exactly
        # this request attribute) -- normally set per-operation by a
        # `csrf_exempt=True` decorator, set here per-request instead,
        # and ONLY on requests this middleware has already positively
        # authenticated via the trusted-proxy boundary above. Plain
        # session-based browser auth (no Authentik headers, or headers
        # from an untrusted peer) never reaches this line, so it stays
        # fully CSRF-checked.
        request._ninja_csrf_exempt = True
        return await self.get_response(request)
