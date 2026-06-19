"""
Mapping between Authentik proxy header values and GlitchTip concepts.

Authentik forwards group membership in a single header (``X-authentik-groups``)
whose value is a pipe-delimited list of group names. Groups relevant to
GlitchTip are tagged with a configurable prefix (default ``glitchtip``), and
the suffix selects the role to apply to the user. Unknown or missing suffixes
are ignored on purpose; the absence of any mapped suffix becomes a denial.
"""

from apps.organizations_ext.constants import OrganizationUserRole


def parse_groups(raw: str) -> list[str]:
    """Split the ``X-authentik-groups`` header value into a clean list."""
    if not raw:
        return []
    return [token.strip() for token in raw.split("|") if token.strip()]


# Suffix → role. The integer values are the OrganizationUserRole choices
# (MEMBER=0, ADMIN=1, MANAGER=2, OWNER=3); ordered by ascending privilege so
# ``max()`` naturally picks the highest matching role.
_SUFFIX_ROLE: dict[str, OrganizationUserRole] = {
    "member": OrganizationUserRole.MEMBER,
    "admin": OrganizationUserRole.ADMIN,
    "manager": OrganizationUserRole.MANAGER,
    "owner": OrganizationUserRole.OWNER,
}


def resolve_role(groups: list[str], prefix: str) -> OrganizationUserRole | None:
    """Return the highest-ranked role implied by ``groups`` or ``None``."""
    if not groups or not prefix:
        return None
    token = f"{prefix}-"
    matched: list[OrganizationUserRole] = []
    for group in groups:
        if not group.startswith(token):
            continue
        suffix = group[len(token) :].strip().lower()
        role = _SUFFIX_ROLE.get(suffix)
        if role is not None:
            matched.append(role)
    if not matched:
        return None
    return max(matched)
