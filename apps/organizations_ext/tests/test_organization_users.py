import json
from typing import ClassVar

from django.core import mail
from django.core.cache import cache
from django.db import transaction
from django.test import TestCase, override_settings
from django.urls import reverse
from model_bakery import baker

from ..constants import OrganizationUserRole
from ..models import OrganizationUser


class OrganizationUsersTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = baker.make("users.user")
        cls.organization = baker.make(
            "organizations_ext.Organization",
            name="<a>No</a><script>HtmlInOrgName</script>",
        )
        cls.org_user = cls.organization.add_user(cls.user)
        baker.make("organizations_ext.OrganizationUser", user=cls.user, role=5)
        cls.members_url = reverse(
            "api:list_organization_members", args=[cls.organization.slug]
        )

    def setUp(self):
        self.client.force_login(self.user)

    def get_org_member_detail_url(self, organization_slug, pk):
        return reverse("api:get_organization_member", args=[organization_slug, pk])

    def test_organization_members_list(self):
        res = self.client.get(self.members_url)
        self.assertContains(res, self.user.email)
        data = res.json()
        self.assertNotIn("teams", data[0].keys())

    def test_organization_members_email_field(self):
        """
        Org Member email should refer to the invited email before acceptance
        After acceptance, it should refer to the user's primary email address
        """
        url = self.get_org_member_detail_url(self.organization.slug, self.org_user.pk)
        res = self.client.get(url)
        self.assertEqual(res.json()["email"], self.user.email)

    def test_organization_team_members_list(self):
        team = baker.make("teams.Team", organization=self.organization)
        url = reverse(
            "api:list_team_organization_members",
            args=[self.organization.slug, team.slug],
        )
        res = self.client.get(url)
        self.assertNotContains(res, self.user.email)

        team.members.add(self.org_user)
        res = self.client.get(url)
        self.assertContains(res, self.user.email)

    def test_organization_members_detail(self):
        other_user = baker.make("users.user")
        other_organization = baker.make("organizations_ext.Organization")
        other_org_user = other_organization.add_user(other_user)
        team = baker.make("teams.Team", organization=self.organization)
        team.members.add(self.org_user)

        url = self.get_org_member_detail_url(self.organization.slug, self.org_user.pk)
        res = self.client.get(url)
        self.assertContains(res, self.user.email)
        self.assertContains(res, team.slug)
        self.assertNotContains(res, other_user.email)

        url = self.get_org_member_detail_url(self.organization.slug, other_org_user.pk)
        res = self.client.get(url)
        self.assertEqual(res.status_code, 404)

    def test_organization_users_add_team_member(self):
        team = baker.make("teams.Team", organization=self.organization)
        url = (
            self.get_org_member_detail_url(self.organization.slug, self.org_user.pk)
            + f"teams/{team.slug}/"
        )

        self.assertEqual(team.members.count(), 0)
        res = self.client.post(url)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(team.members.count(), 1)

        res = self.client.delete(url)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(team.members.count(), 0)

    def test_organization_users_add_self_team_member(self):
        team = baker.make("teams.Team", organization=self.organization)
        url = reverse(
            "api:add_member_to_team", args=[self.organization.slug, "me", team.slug]
        )

        self.assertEqual(team.members.count(), 0)
        res = self.client.post(url)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(team.members.count(), 1)

        res = self.client.delete(url)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(team.members.count(), 0)

    def test_organization_users_create_and_accept_invite(self):
        data = {
            "email": "new@example.com",
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [],
        }
        res = self.client.post(self.members_url, data, content_type="application/json")
        self.assertTrue(res.json()["pending"])

        self.assertEqual(mail.outbox[0].extra_headers["X-Mailer"], "GlitchTip")

        body = mail.outbox[0].body
        html_content = mail.outbox[0].alternatives[0][0]
        self.assertFalse("<a>No</a><script>HtmlInOrgName</script>" in body)
        self.assertTrue("NoHtmlInOrgName" in body)
        self.assertFalse("<a>No</a><script>HtmlInOrgName</script>" in html_content)
        self.assertTrue("NoHtmlInOrgName" in html_content)
        body_split = body[body.find("http://localhost:8000/accept/") :].split("/")
        org_user_id = body_split[4]
        token = body_split[5]
        url = reverse("api:get_accept_invite", args=[org_user_id, token])

        # Check that we can determine organization name from GET request to accept invite endpoint
        self.client.logout()
        res = self.client.get(url)
        self.assertContains(res, self.organization.name)

        user = baker.make("users.user")
        self.client.force_login(user)
        data = {"acceptInvite": True}
        res = self.client.post(url, data, content_type="application/json")
        self.assertContains(res, self.organization.name)
        self.assertFalse(res.json()["orgUser"]["pending"])
        self.assertTrue(
            OrganizationUser.objects.filter(
                user=user, organization=self.organization
            ).exists()
        )

    @override_settings(
        EMAIL_INVITE_THROTTLE_COUNT=1,
        EMAIL_INVITE_REQUIRE_VERIFICATION=True,
    )
    def test_organization_users_create_throttle(self):
        cache_key = f"email_invite_throttle_{self.user.id}"
        cache.delete(cache_key)
        data = {
            "email": "new@example.com",
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [],
        }
        res = self.client.post(self.members_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 403)

        self.user.emailaddress_set.create(email="new@example.com", verified=True)

        res = self.client.post(self.members_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 201)
        res = self.client.post(self.members_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 429)

        def test_org_name_url_chars_stripped(self):
            self.organization.name = "visit https://evilspam.com"
            self.organization.save()

            data = {
                "email": "new@example.com",
                "orgRole": OrganizationUserRole.MANAGER.label.lower(),
                "teamRoles": [],
            }
            self.client.post(self.members_url, data, content_type="application/json")

            self.assertEqual(mail.outbox[0].extra_headers["X-Mailer"], "GlitchTip")

            body = mail.outbox[0].body
            html_content = mail.outbox[0].alternatives[0][0]
            self.assertFalse("visit https://evilspam.com" in body)
            self.assertTrue("visit sevilspam" in body)
            self.assertFalse("visit https://evilspam.com" in html_content)
            self.assertTrue("visit sevilspam" in html_content)

    def test_closed_user_registration(self):
        data = {
            "email": "new@example.com",
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [],
        }

        with override_settings(ENABLE_USER_REGISTRATION=False):
            # Non-existing user cannot be invited
            res = self.client.post(
                self.members_url, data, content_type="application/json"
            )
            self.assertEqual(res.status_code, 403)

            # Existing user can be invited
            self.user = baker.make("users.user", email="new@example.com")
            res = self.client.post(
                self.members_url, data, content_type="application/json"
            )
            self.assertEqual(res.status_code, 201)

    def test_organization_users_invite_twice(self):
        """Don't allow inviting user who is already in the group"""
        data = {
            "email": "new@example.com",
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [],
            "reinvite": False,
        }
        res = self.client.post(self.members_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 201)
        with transaction.atomic():
            res = self.client.post(
                self.members_url, data, content_type="application/json"
            )
        self.assertEqual(res.status_code, 409)
        data["email"] = self.user.email
        res = self.client.post(self.members_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 409)

    def test_organization_users_create(self):
        team = baker.make("teams.Team", organization=self.organization)
        data = {
            "email": "new@example.com",
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [{"teamSlug": team.slug}],
        }
        res = self.client.post(
            self.members_url, json.dumps(data), content_type="application/json"
        )
        self.assertContains(res, data["email"], status_code=201)
        self.assertEqual(res.json()["role"], "manager")
        self.assertTrue(
            OrganizationUser.objects.filter(
                organization=self.organization,
                email=data["email"],
                user=None,
                role=OrganizationUserRole.MANAGER,
            ).exists()
        )
        self.assertTrue(team.members.exists())
        self.assertEqual(len(mail.outbox), 1)

    def test_organization_users_create_and_accept(self):
        data = {
            "email": "new@example.com",
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [],
        }
        self.client.post(self.members_url, data, content_type="application/json")

        self.assertEqual(mail.outbox[0].extra_headers["X-Mailer"], "GlitchTip")

        body = mail.outbox[0].body
        body[body.find("http://localhost:8000/accept/") :].split("/")[4]

    def test_organization_users_create_without_permissions(self):
        """Admin cannot add users to org"""
        other_user = baker.make("users.user")
        self.organization.add_user(other_user, role=OrganizationUserRole.MANAGER)
        self.org_user.role = OrganizationUserRole.ADMIN
        self.org_user.save()
        data = {
            "email": "new@example.com",
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [],
        }
        res = self.client.post(self.members_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 403)

    def test_organization_users_create_without_org_specific_permissions(self):
        """
        Ensure queryset with role_required checks the correct organization user's role.
        """

        organization_2 = baker.make("organizations_ext.Organization")
        org_2_user = organization_2.add_user(self.user)
        org_2_user.role = OrganizationUserRole.ADMIN
        org_2_user.save()

        data = {
            "email": "new@example.com",
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [],
        }
        url = reverse("api:list_organization_members", args=[organization_2.slug])
        res = self.client.post(url, data, content_type="application/json")
        self.assertEqual(res.status_code, 403)

        org_2_user.role = OrganizationUserRole.MANAGER
        org_2_user.save()

        res = self.client.post(url, data, content_type="application/json")
        self.assertTrue(
            OrganizationUser.objects.filter(
                organization=organization_2,
                email=data["email"],
                user=None,
                role=OrganizationUserRole.MANAGER,
            ).exists()
        )

    def test_organization_users_reinvite(self):
        other_user = baker.make("users.user")
        baker.make(
            "organizations_ext.OrganizationUser",
            email=other_user.email,
            organization=self.organization,
        )

        data = {
            "email": other_user.email,
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [],
        }
        res = self.client.post(self.members_url, data, content_type="application/json")
        self.assertContains(res, other_user.email, status_code=201)
        self.assertTrue(len(mail.outbox))

    def test_organization_users_update(self):
        other_user = baker.make("users.user")
        other_org_user = self.organization.add_user(other_user)

        url = self.get_org_member_detail_url(self.organization.slug, other_org_user.pk)

        new_role = OrganizationUserRole.ADMIN
        data = {"orgRole": new_role.label.lower(), "teamRoles": []}
        res = self.client.put(url, data, content_type="application/json")
        self.assertContains(res, other_user.email)
        self.assertTrue(
            OrganizationUser.objects.filter(
                organization=self.organization, role=new_role, user=other_user
            ).exists()
        )

    def test_organization_users_update_ownerless_org(self):
        """Do not allow ownerless organizations"""
        url = self.get_org_member_detail_url(self.organization.slug, self.org_user.pk)
        data = {"orgRole": OrganizationUserRole.MEMBER.label.lower(), "teamRoles": []}
        res = self.client.put(url, data, content_type="application/json")
        self.assertEqual(res.status_code, 422)

    def test_organization_users_update_without_permissions(self):
        self.org_user.role = OrganizationUserRole.ADMIN
        self.org_user.save()
        other_user = baker.make("users.user")
        other_org_user = self.organization.add_user(other_user)

        url = self.get_org_member_detail_url(self.organization.slug, other_org_user.pk)

        new_role = OrganizationUserRole.ADMIN
        data = {"orgRole": new_role.label.lower(), "teamRoles": []}
        res = self.client.put(url, data, content_type="application/json")
        self.assertEqual(res.status_code, 403)

    def test_organization_users_delete(self):
        other_user = baker.make("users.user")
        other_org_user = self.organization.add_user(other_user)

        url = self.get_org_member_detail_url(self.organization.slug, other_org_user.pk)

        res = self.client.delete(url)
        self.assertEqual(res.status_code, 204)
        self.assertEqual(other_user.organizations_ext_organizationuser.count(), 0)

        url = self.get_org_member_detail_url(self.organization.slug, self.org_user.pk)
        res = self.client.delete(url)
        self.assertEqual(
            res.status_code,
            400,
            "Org owner should not be able to remove themselves from org",
        )

        third_user = baker.make("users.user")
        third_org_user = self.organization.add_user(third_user)
        change_ownership_url = (
            self.get_org_member_detail_url(self.organization.slug, third_org_user.pk)
            + "set_owner/"
        )
        self.client.post(change_ownership_url)

        res = self.client.delete(url)
        self.assertEqual(
            res.status_code,
            204,
            "Can remove self after transferring ownership",
        )

    def test_organization_users_delete_without_permissions(self):
        self.org_user.role = OrganizationUserRole.ADMIN
        self.org_user.save()
        other_user = baker.make("users.user")
        other_org_user = self.organization.add_user(other_user)

        url = self.get_org_member_detail_url(self.organization.slug, other_org_user.pk)

        res = self.client.delete(url)
        self.assertEqual(res.status_code, 403)
        self.assertEqual(other_user.organizations_ext_organizationuser.count(), 1)

    def test_organization_users_delete_self(self):
        other_user = baker.make("users.user")
        other_org_user = self.organization.add_user(other_user)

        self.client.force_login(other_user)

        url = self.get_org_member_detail_url(self.organization.slug, other_org_user.pk)

        res = self.client.delete(url)
        self.assertEqual(res.status_code, 204)
        self.assertEqual(other_user.organizations_ext_organizationuser.count(), 0)

    def test_organization_members_set_owner(self):
        other_user = baker.make("users.user")
        other_org_user = self.organization.add_user(other_user)
        random_org_user = baker.make("organizations_ext.OrganizationUser")

        url = reverse(
            "api:set_organization_owner",
            args=[self.organization.slug, random_org_user.pk],
        )
        res = self.client.post(url)
        self.assertEqual(
            res.status_code, 404, "Don't set random unrelated users as owner"
        )

        url = (
            self.get_org_member_detail_url(self.organization.slug, other_org_user.pk)
            + "set_owner/"
        )
        res = self.client.post(url)
        self.assertTrue(
            res.json()["isOwner"], "Current owner may set another org member as owner"
        )

        url = reverse(
            "api:set_organization_owner",
            args=[self.organization.slug, self.org_user.pk],
        )
        url = (
            self.get_org_member_detail_url(self.organization.slug, self.org_user.pk)
            + "set_owner/"
        )
        self.org_user.role = OrganizationUserRole.MANAGER
        self.org_user.save()
        res = self.client.post(url)
        self.assertEqual(
            res.status_code, 403, "Can't set self as owner with only manager role"
        )

        self.org_user.role = OrganizationUserRole.OWNER
        self.org_user.save()
        res = self.client.post(url)
        self.assertTrue(res.json()["isOwner"], "Owner role may set org member as owner")


class AuthentikInviteAcceptanceTestCase(TestCase):
    """Regression test: accepting an org invitation via Authentik
    proxy headers must attach ``request.auth.user_id`` to the pending
    invite row, the same as it does for session-authenticated callers.

    ``apps.organizations_ext.api.accept_invite`` historically used
    ``await aget_user(request)`` to identify the accepting user. The
    Authentik proxy middleware does NOT log anyone in (no Django
    session), so the fix replaces that lookup with
    ``User.objects.aget(id=request.auth.user_id)`` -- which works for
    Token, Session, AND Authentik auth classes.

    The Authentik middleware also runs ``sync_org_memberships`` on
    first sight of the email, which would otherwise create a second
    ``OrganizationUser`` row for (org, user=X) and trip the
    (user, organization) UNIQUE constraint when the accept binds the
    invite. To exercise the SUCCESS path cleanly, this test
    pre-primes the per-user role-sync cache so sync is a no-op.
    """

    AUTHENTIK_SETTINGS: ClassVar[dict] = {
        "AUTHENTIK_PROXY_AUTH_ENABLED": True,
        "AUTHENTIK_TRUSTED_PROXIES": ["10.0.0.1"],
        "AUTHENTIK_GROUP_PREFIX": "glitchtip",
        "AUTHENTIK_ROLE_SYNC_CACHE_TTL": 300,
    }

    @classmethod
    def setUpTestData(cls):
        cls.owner = baker.make("users.user")
        cls.organization = baker.make("organizations_ext.Organization")
        cls.organization.add_user(cls.owner, OrganizationUserRole.OWNER)
        cls.members_url = reverse(
            "api:list_organization_members", args=[cls.organization.slug]
        )

    def setUp(self):
        # Owner (session-auth) creates the invite.
        self.client.force_login(self.owner)

    def _create_invite(self, email: str) -> tuple[str, str]:
        """Return ``(org_user_id, token)`` extracted from the invite email."""
        data = {
            "email": email,
            "orgRole": OrganizationUserRole.MANAGER.label.lower(),
            "teamRoles": [],
        }
        res = self.client.post(self.members_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 201)
        body = mail.outbox[-1].body
        body_split = body[body.find("http://localhost:8000/accept/") :].split("/")
        return body_split[4], body_split[5]

    @override_settings(**AUTHENTIK_SETTINGS)
    def test_authentik_accept_invite_attaches_invited_user(self):
        """SSO caller accepts an invite; the resolved user is bound
        to the invite row and the email is cleared."""
        from apps.authentik_auth.mapping import parse_groups
        from apps.authentik_auth.provisioning import groups_hash
        from apps.users.models import User

        invited_email = "lara@example.com"
        org_user_id, token = self._create_invite(invited_email)

        # Pre-create the Authentik-side user so JIT is a no-op and we
        # can pre-prime the role-sync cache. With the cache primed,
        # ``sync_org_memberships`` returns immediately and does NOT
        # create a duplicate ``OrganizationUser`` row that would
        # otherwise collide with the invite row on save.
        invited_user = User.objects.create(email=invited_email, is_active=True)
        groups = parse_groups("glitchtip-member")
        cache.set(f"authentik_roles:{invited_user.id}:{groups_hash(groups)}", True)

        # The api-level auth chain is ``[TokenAuth, SessionAuth,
        # AuthentikHeaderAuth]`` (glitchtip/api/api.py:55) and runs in
        # order. ``setUp`` force-logs in the OWNER, so without this
        # logout ``SessionAuth`` would short-circuit the chain BEFORE
        # ``AuthentikHeaderAuth`` is ever consulted and the invite
        # would be bound to the owner (who is already a member of the
        # org, so the unique_together would trip and the test would
        # fail for the wrong reason, masking the real bug).
        self.client.logout()

        url = reverse("api:get_accept_invite", args=[org_user_id, token])
        response = self.client.post(
            url,
            data=json.dumps({"acceptInvite": True}),
            content_type="application/json",
            REMOTE_ADDR="10.0.0.1",
            HTTP_X_AUTHENTIK_EMAIL=invited_email,
            HTTP_X_AUTHENTIK_NAME="Lara",
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-member",
        )

        # The fix routes identity resolution through request.auth, so
        # the invite row is rebound to the Authentik-provisioned user
        # instead of the (anonymous) session user.
        self.assertEqual(response.status_code, 200)
        org_user = OrganizationUser.objects.get(pk=org_user_id)
        self.assertEqual(org_user.user_id, invited_user.id)
        self.assertIsNone(org_user.email)
        self.assertFalse(org_user.pending)

    @override_settings(**AUTHENTIK_SETTINGS)
    def test_authentik_accept_invite_survives_a_live_role_sync(self):
        """Regression test for the duplicate-membership race, exercised
        with NO cache priming -- this is the actual first-contact path a
        real invited user takes, not the artificially-quieted success
        path the test above proves.

        AuthentikProxyMiddleware runs on this very POST (and on any
        earlier authenticated request the invited user made) and calls
        ``sync_org_memberships``, which iterates every non-deleted org
        including the one this invite is for. Before
        ``apps.authentik_auth.provisioning.sync_org_memberships`` learned
        to skip an org with a pending invite matching the user's email,
        that call created a SEPARATE ``OrganizationUser(user=invited_
        user)`` row here, and this test's own accept POST then collided
        with it on the ``(user, organization)`` unique constraint --
        turning an ordinary invite acceptance into an unhandled 500.
        """
        invited_email = "noor@example.com"
        org_user_id, token = self._create_invite(invited_email)

        self.client.logout()

        url = reverse("api:get_accept_invite", args=[org_user_id, token])
        response = self.client.post(
            url,
            data=json.dumps({"acceptInvite": True}),
            content_type="application/json",
            REMOTE_ADDR="10.0.0.1",
            HTTP_X_AUTHENTIK_EMAIL=invited_email,
            HTTP_X_AUTHENTIK_NAME="Noor",
            HTTP_X_AUTHENTIK_GROUPS="glitchtip-member",
        )

        self.assertEqual(response.status_code, 200)
        org_user = OrganizationUser.objects.get(pk=org_user_id)
        self.assertIsNotNone(org_user.user_id)
        self.assertEqual(org_user.user.email, invited_email)
        self.assertFalse(org_user.pending)
        # Exactly one membership row exists for (user, organization) --
        # the pending invite row itself, now bound. sync_org_memberships
        # must not have created a second, competing row.
        self.assertEqual(
            OrganizationUser.objects.filter(
                organization_id=org_user.organization_id,
                user_id=org_user.user_id,
            ).count(),
            1,
        )

    def test_authentik_accept_invite_succeeds_without_csrf_token(self):
        """Regression test for the CSRF-on-SSO-POST bug.

        ninja's auth chain is ``[TokenAuth, SessionAuth,
        AuthentikHeaderAuth]`` (glitchtip/api/api.py:55); ``SessionAuth``
        extends ninja's ``APIKeyCookie``, which runs Django's CSRF check
        BEFORE ``AuthentikHeaderAuth`` is ever reached. The default test
        client sets ``enforce_csrf_checks=False``, which is why every
        other test in this file -- including the two above -- would pass
        even if this bug were still present. This test turns CSRF
        enforcement back on to prove the fix in
        ``AuthentikProxyMiddleware`` (setting ``request._ninja_csrf_exempt``
        on requests it has already authenticated via the trusted-proxy
        boundary) actually works.
        """
        from django.test import Client

        from apps.authentik_auth.mapping import parse_groups
        from apps.authentik_auth.provisioning import groups_hash
        from apps.users.models import User

        invited_email = "mia@example.com"
        org_user_id, token = self._create_invite(invited_email)

        invited_user = User.objects.create(email=invited_email, is_active=True)
        groups = parse_groups("glitchtip-member")
        cache.set(f"authentik_roles:{invited_user.id}:{groups_hash(groups)}", True)

        self.client.logout()

        csrf_client = Client(enforce_csrf_checks=True)
        url = reverse("api:get_accept_invite", args=[org_user_id, token])
        with override_settings(**self.AUTHENTIK_SETTINGS):
            response = csrf_client.post(
                url,
                data=json.dumps({"acceptInvite": True}),
                content_type="application/json",
                REMOTE_ADDR="10.0.0.1",
                HTTP_X_AUTHENTIK_EMAIL=invited_email,
                HTTP_X_AUTHENTIK_NAME="Mia",
                HTTP_X_AUTHENTIK_GROUPS="glitchtip-member",
            )

        self.assertEqual(response.status_code, 200)
        org_user = OrganizationUser.objects.get(pk=org_user_id)
        self.assertEqual(org_user.user_id, invited_user.id)
