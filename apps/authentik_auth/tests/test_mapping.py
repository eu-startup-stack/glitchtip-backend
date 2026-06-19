"""
Unit tests for the Authentik header → role mapping helpers.

These tests don't touch the database — the mapping is pure logic over
the incoming header values.
"""

from django.test import SimpleTestCase

from apps.authentik_auth.mapping import parse_groups, resolve_role
from apps.organizations_ext.constants import OrganizationUserRole


class ParseGroupsTests(SimpleTestCase):
    def test_splits_on_pipe(self):
        self.assertEqual(
            parse_groups("glitchtip-admin|glitchtip-member"),
            ["glitchtip-admin", "glitchtip-member"],
        )

    def test_strips_whitespace(self):
        self.assertEqual(
            parse_groups("  glitchtip-admin | glitchtip-member  "),
            ["glitchtip-admin", "glitchtip-member"],
        )

    def test_drops_empty_tokens(self):
        self.assertEqual(
            parse_groups("|glitchtip-admin||glitchtip-member|"),
            ["glitchtip-admin", "glitchtip-member"],
        )

    def test_empty_string_returns_empty_list(self):
        self.assertEqual(parse_groups(""), [])

    def test_none_returns_empty_list(self):
        self.assertEqual(parse_groups(None), [])  # type: ignore[arg-type]

    def test_only_pipes_returns_empty_list(self):
        self.assertEqual(parse_groups("|||"), [])


class ResolveRoleTests(SimpleTestCase):
    def test_member_mapping(self):
        self.assertEqual(
            resolve_role(["glitchtip-member"], "glitchtip"),
            OrganizationUserRole.MEMBER,
        )

    def test_admin_mapping(self):
        self.assertEqual(
            resolve_role(["glitchtip-admin"], "glitchtip"),
            OrganizationUserRole.ADMIN,
        )

    def test_manager_mapping(self):
        self.assertEqual(
            resolve_role(["glitchtip-manager"], "glitchtip"),
            OrganizationUserRole.MANAGER,
        )

    def test_owner_mapping(self):
        self.assertEqual(
            resolve_role(["glitchtip-owner"], "glitchtip"),
            OrganizationUserRole.OWNER,
        )

    def test_mixed_groups_returns_highest(self):
        # admin < manager < owner, so the highest in the list wins.
        self.assertEqual(
            resolve_role(
                ["glitchtip-admin", "glitchtip-owner", "glitchtip-member"],
                "glitchtip",
            ),
            OrganizationUserRole.OWNER,
        )

    def test_unrelated_groups_are_ignored(self):
        self.assertEqual(
            resolve_role(["some-other-group", "admins"], "glitchtip"),
            None,
        )

    def test_unknown_suffix_returns_none(self):
        # Prefix matches but the suffix isn't a known role.
        self.assertEqual(
            resolve_role(["glitchtip-superuser"], "glitchtip"),
            None,
        )

    def test_mix_of_known_and_unknown_suffices(self):
        # A recognised suffix is enough even if other prefixed
        # tokens map to nothing.
        self.assertEqual(
            resolve_role(["glitchtip-superuser", "glitchtip-admin"], "glitchtip"),
            OrganizationUserRole.ADMIN,
        )

    def test_empty_groups_returns_none(self):
        self.assertEqual(resolve_role([], "glitchtip"), None)

    def test_custom_prefix(self):
        self.assertEqual(
            resolve_role(["acme-owner"], "acme"),
            OrganizationUserRole.OWNER,
        )

    def test_custom_prefix_does_not_match_default(self):
        # A 'glitchtip-' group with prefix='acme' must not match.
        self.assertEqual(
            resolve_role(["glitchtip-admin"], "acme"),
            None,
        )

    def test_suffix_is_case_insensitive(self):
        self.assertEqual(
            resolve_role(["glitchtip-ADMIN"], "glitchtip"),
            OrganizationUserRole.ADMIN,
        )

    def test_empty_prefix_returns_none(self):
        # Without a configured prefix no group ever matches, so we
        # never accidentally apply a role on an unconfigured deploy.
        self.assertEqual(resolve_role(["glitchtip-admin"], ""), None)
