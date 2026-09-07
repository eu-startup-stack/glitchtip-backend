"""
Integration tests for the Authentik proxy-header middleware.

These tests run against the real Django test client with the
``AUTHENTIK_PROXY_AUTH_ENABLED`` setting toggled on per-test, and
exercise the full middleware chain (including the allauth adapters
and signup gating). The sync test client drives async middleware
transparently — Django adapts under the hood.
"""

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.organizations_ext.constants import OrganizationUserRole
from apps.organizations_ext.models import (
    Organization,
    OrganizationOwner,
    OrganizationUser,
)
from apps.users.models import User

from ..middleware import (
    _HEALTH_EXEMPT_PATHS,
    _is_trusted_proxy,
    _strip_authentik_headers,
)

_TRUSTED_PROXY = "10.0.0.1"
_UNTRUSTED_PROXY = "203.0.113.9"
_AUTHENTIK_BASE = {
    "AUTHENTIK_PROXY_AUTH_ENABLED": True,
    "AUTHENTIK_TRUSTED_PROXIES": [_TRUSTED_PROXY],
    "AUTHENTIK_GROUP_PREFIX": "glitchtip",
    "AUTHENTIK_ROLE_SYNC_CACHE_TTL": 300,
}


def _override(**extra):
    return override_settings(**{**_AUTHENTIK_BASE, **extra})


class TrustedProxyHelperTests(TestCase):
    def test_exact_ip_match(self):
        with _override():
            self.assertTrue(_is_trusted_proxy(_TRUSTED_PROXY))

    def test_cidr_match(self):
        with _override(AUTHENTIK_TRUSTED_PROXIES=["10.0.0.0/24"]):
            self.assertTrue(_is_trusted_proxy("10.0.0.42"))

    def test_untrusted_ip(self):
        with _override():
            self.assertFalse(_is_trusted_proxy(_UNTRUSTED_PROXY))

    def test_empty_peer(self):
        with _override():
            self.assertFalse(_is_trusted_proxy(""))

    def test_no_trusted_proxies_configured(self):
        with _override(AUTHENTIK_TRUSTED_PROXIES=[]):
            self.assertFalse(_is_trusted_proxy(_TRUSTED_PROXY))

    def test_garbage_peer_does_not_match(self):
        with _override():
            self.assertFalse(_is_trusted_proxy("not-an-ip"))

    def test_invalid_cidr_is_ignored(self):
        # Invalid entries are skipped silently instead of crashing the
        # request path. The deploy would be broken at startup anyway.
        with _override(AUTHENTIK_TRUSTED_PROXIES=["not-a-cidr"]):
            self.assertFalse(_is_trusted_proxy(_TRUSTED_PROXY))


class StripAuthentikHeadersTests(TestCase):
    def test_strips_all_authentik_headers(self):
        from django.test import RequestFactory

        request = RequestFactory().get("/")
        request.META["HTTP_X_AUTHENTIK_EMAIL"] = "x@y"
        request.META["HTTP_X_AUTHENTIK_NAME"] = "x"
        request.META["HTTP_X_AUTHENTIK_GROUPS"] = "g"
        request.META["HTTP_X_AUTHENTIK_USERNAME"] = "x"
        request.META["HTTP_X_FORWARDED_FOR"] = "irrelevant"
        _strip_authentik_headers(request)
        self.assertNotIn("HTTP_X_AUTHENTIK_EMAIL", request.META)
        self.assertNotIn("HTTP_X_AUTHENTIK_NAME", request.META)
        self.assertNotIn("HTTP_X_AUTHENTIK_GROUPS", request.META)
        self.assertNotIn("HTTP_X_AUTHENTIK_USERNAME", request.META)
        self.assertIn("HTTP_X_FORWARDED_FOR", request.META)


@_override()
class AuthentikMiddlewareTestCase(TestCase):
    """Drive the full middleware via the sync test client."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self.organization = Organization.objects.create(
            name="Test Org", slug="test-org"
        )
        # Seed an existing member so the new JIT user is NOT the
        # org's first member (which would otherwise force OWNER via
        # the ownerless guard and hide the role-under-test).
        seeder = User.objects.create(email="seeder@example.com", is_active=True)
        self.organization.add_user(seeder, OrganizationUserRole.OWNER)

    # --- 1. trusted + valid role -> 200 + user is created/joined ---
    def test_trusted_proxy_authenticates_user_and_joins_org(self):
        email = "alice@example.com"
        response = self.client.get(
            "/api/0/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL=email,
            HTTP_X_AUTHENTIK_NAME="Alice",
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-admin",
        )
        # /api/0/ is auth=None so it always returns 200. The proof of
        # authentication is the side-effects: the user was created and
        # joined to the org with the resolved role.
        self.assertEqual(response.status_code, 200)
        # JIT user was created with the supplied name and email.
        user = User.objects.get(email=email)
        self.assertEqual(user.name, "Alice")
        self.assertTrue(user.is_active)
        # Org sync gave them ADMIN membership.
        org_user = OrganizationUser.objects.get(
            organization=self.organization, user=user
        )
        self.assertEqual(org_user.role, OrganizationUserRole.ADMIN)

    # --- 2. trusted + no role -> 403 ---
    def test_trusted_proxy_without_role_is_rejected(self):
        response = self.client.get(
            "/api/0/organizations/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL="bob@example.com",
            HTTP_X_AUTHENTIK_GROUPS="some-other-group",
        )
        self.assertEqual(response.status_code, 403)
        # No user should be created for a denied request.
        self.assertFalse(User.objects.filter(email="bob@example.com").exists())

    # --- 3. untrusted IP -> headers stripped, no auth ---
    def test_untrusted_peer_cannot_inject_headers(self):
        response = self.client.get(
            "/api/0/organizations/",
            REMOTE_ADDR=_UNTRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL="mallory@example.com",
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-admin",
        )
        # No authentik user was provisioned for the spoofed identity.
        self.assertFalse(User.objects.filter(email="mallory@example.com").exists())
        # The downstream endpoint requires auth, so an unauthenticated
        # client gets the default 401 from django-ninja.
        self.assertEqual(response.status_code, 401)

    # --- 4. feature disabled -> middleware is a no-op ---
    def test_disabled_setting_does_not_authenticate(self):
        with override_settings(AUTHENTIK_PROXY_AUTH_ENABLED=False):
            response = self.client.get(
                "/api/0/organizations/",
                REMOTE_ADDR=_TRUSTED_PROXY,
                HTTP_X_AUTHENTIK_EMAIL="carol@example.com",
                HTTP_X_AUTHENTIK_GROUPS="glitchtip-admin",
            )
        # Without the feature on, headers should not be honoured.
        self.assertFalse(User.objects.filter(email="carol@example.com").exists())
        self.assertEqual(response.status_code, 401)

    # --- 5. health endpoint exempt from 403 ---
    def test_health_endpoint_passes_through_without_role(self):
        for path in _HEALTH_EXEMPT_PATHS:
            response = self.client.get(
                path,
                REMOTE_ADDR=_TRUSTED_PROXY,
                HTTP_X_AUTHENTIK_EMAIL="dan@example.com",
                HTTP_X_AUTHENTIK_GROUPS="some-other-group",
            )
            self.assertEqual(response.status_code, 200, msg=f"path={path}")
        # Health-exempt must not JIT-provision a user: a probe carrying
        # X-authentik-email but no glitchtip- group must not mint an
        # account or stash auth on the request.
        self.assertFalse(User.objects.filter(email="dan@example.com").exists())

    # --- 6. JIT sets name + verified primary EmailAddress ---
    def test_jit_creates_verified_primary_email_address(self):
        email = "erin@example.com"
        self.client.get(
            "/api/0/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL=email,
            HTTP_X_AUTHENTIK_NAME="Erin",
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-member",
        )
        from allauth.account.models import EmailAddress

        ea = EmailAddress.objects.get(email=email)
        self.assertTrue(ea.verified)
        self.assertTrue(ea.primary)
        user = ea.user
        self.assertEqual(user.name, "Erin")

    # --- additional: org sync promotes first member to OWNER ---
    def test_first_org_member_becomes_owner(self):
        email = "frank@example.com"
        # Fresh org with no existing members.
        new_org = Organization.objects.create(name="Empty Org", slug="empty-org")
        self.client.get(
            "/api/0/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL=email,
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-member",
        )
        user = User.objects.get(email=email)
        org_user = OrganizationUser.objects.get(organization=new_org, user=user)
        # The first (only) member is forced to OWNER so the org is
        # never left without one.
        self.assertEqual(org_user.role, OrganizationUserRole.OWNER)

    # --- additional: existing primary OWNER is never demoted ---
    def test_primary_owner_is_not_demoted(self):
        email = "gina@example.com"
        # Pre-seed a user that's the primary owner of the test org.
        existing = User.objects.create(email=email, name="Gina", is_active=True)
        existing_org_user = self.organization.add_user(
            existing, OrganizationUserRole.OWNER
        )
        OrganizationOwner.objects.create(
            organization=self.organization, organization_user=existing_org_user
        )
        # Authentik now claims this user is a MEMBER (a downgrade).
        self.client.get(
            "/api/0/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL=email,
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-member",
        )
        existing_org_user.refresh_from_db()
        # The primary owner is protected — role remains OWNER.
        self.assertEqual(existing_org_user.role, OrganizationUserRole.OWNER)

    # --- additional: cache skip avoids re-syncing on repeat requests ---
    def test_repeat_requests_skip_sync(self):
        email = "henry@example.com"
        # First request does the real sync and primes the cache.
        self.client.get(
            "/api/0/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL=email,
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-admin",
        )
        user = User.objects.get(email=email)
        org_user = OrganizationUser.objects.get(
            organization=self.organization, user=user
        )
        # Sanity: the first sync applied ADMIN.
        self.assertEqual(org_user.role, OrganizationUserRole.ADMIN)
        # Manually mutate the role to a different value to prove a
        # second request is a cache-hit and does NOT re-apply the
        # resolved role.
        org_user.role = OrganizationUserRole.MEMBER
        org_user.save(update_fields=["role"])
        self.client.get(
            "/api/0/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL=email,
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-admin",
        )
        org_user.refresh_from_db()
        # Cached: the second request did NOT re-sync, so the manual
        # edit survives.
        self.assertEqual(org_user.role, OrganizationUserRole.MEMBER)

    # --- additional: API root returns the Authentik-provisioned user ---
    def test_api_root_returns_authentik_user(self):
        """/api/0/ is auth-free so django-ninja's auth chain does not run.

        The Authentik proxy middleware still provisions a local ``User``
        and stashes the identity on ``request.authentik_auth``. The view
        must surface that user (not just ``null``) so the SPA knows who
        it is talking to on first paint.
        """
        email = "ivy@example.com"
        response = self.client.get(
            "/api/0/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL=email,
            HTTP_X_AUTHENTIK_NAME="Ivy",
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-member",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        # The narrow-fallback in api_root must populate user from the
        # Authentik auth object, not from the (anonymous) session.
        self.assertIsNotNone(body["user"])
        self.assertEqual(body["user"]["email"], email)
        self.assertEqual(body["user"]["name"], "Ivy")

    # --- JIT reconciliation: demote a pre-existing primary email ---
    def test_jit_replaces_different_primary_email(self):
        """A user with a different primary email (e.g. left over from
        password signup before Authentik took over) must have that
        primary demoted when Authentik later sends a new address, and
        the Authentik address must end up verified + primary.

        Without the ordered reconciliation in provisioning this call
        trips allauth's partial UNIQUE constraint on (user, primary)
        WHERE primary=True and the request 500s.
        """
        from allauth.account.models import EmailAddress

        new_email = "jack-new@example.com"
        old_email = "jack-old@example.com"
        # Pre-existing user with a verified primary email that is NOT
        # the email Authentik will send. This is the typical "we moved
        # from password signup to SSO" migration case.
        existing_user = User.objects.create(email=old_email, is_active=True)
        old_address = EmailAddress.objects.create(
            user=existing_user, email=old_email, verified=True, primary=True
        )
        # Sanity: the seeded row really is the user's only primary.
        self.assertTrue(old_address.primary)

        response = self.client.get(
            "/api/0/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL=new_email,
            HTTP_X_AUTHENTIK_NAME="Jack",
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-member",
        )
        self.assertEqual(response.status_code, 200)

        # The new Authentik address exists, is verified, and is primary.
        new_address = EmailAddress.objects.get(user=existing_user, email=new_email)
        self.assertTrue(new_address.verified)
        self.assertTrue(new_address.primary)

        # The old primary was demoted (NOT deleted, NOT still primary).
        old_address.refresh_from_db()
        self.assertFalse(old_address.primary)
        self.assertTrue(old_address.verified)

        # Exactly one primary row exists for this user, no matter how
        # many legacy rows the user accumulated.
        primaries = EmailAddress.objects.filter(user=existing_user, primary=True)
        self.assertEqual(primaries.count(), 1)
        self.assertEqual(primaries.first().email, new_email)

    def test_jit_promotes_existing_authentik_email_to_primary(self):
        """When a pre-existing non-primary EmailAddress row matches the
        Authentik-supplied email, JIT must promote it to primary after
        demoting whatever was primary before.
        """
        from allauth.account.models import EmailAddress

        new_email = "kira-new@example.com"
        old_email = "kira-old@example.com"
        existing_user = User.objects.create(email=new_email, is_active=True)
        # Pre-existing primary that we'll need to demote.
        old_address = EmailAddress.objects.create(
            user=existing_user, email=old_email, verified=True, primary=True
        )
        # Pre-existing Authentik row, but as a non-primary secondary
        # (e.g. left over from a previous request where reconciliation
        # didn't run).
        new_address = EmailAddress.objects.create(
            user=existing_user, email=new_email, verified=False, primary=False
        )

        response = self.client.get(
            "/api/0/",
            REMOTE_ADDR=_TRUSTED_PROXY,
            HTTP_X_AUTHENTIK_EMAIL=new_email,
            HTTP_X_AUTHENTIK_NAME="Kira",
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-member",
        )
        self.assertEqual(response.status_code, 200)

        new_address.refresh_from_db()
        old_address.refresh_from_db()
        self.assertTrue(new_address.primary)
        self.assertTrue(new_address.verified)
        self.assertFalse(old_address.primary)

        primaries = EmailAddress.objects.filter(user=existing_user, primary=True)
        self.assertEqual(primaries.count(), 1)
        self.assertEqual(primaries.first().email, new_email)
