"""
Provisioning side-effects for Authentik-authenticated requests.

Authentik handles authentication; this module makes the resulting
identity and role exist inside GlitchTip:

* On first sight of an email, create the local ``User`` row plus the
  allauth ``EmailAddress`` so the SPA's email-management UI stays happy.
* Mirror the resolved role onto ``OrganizationUser`` rows for every
  non-deleted organization. Cached per ``(user, groups_hash)`` so the
  hot request path skips the DB once a sync has run.
"""

import hashlib

from allauth.account.models import EmailAddress
from django.conf import settings
from django.core.cache import cache

from apps.organizations_ext.constants import OrganizationUserRole
from apps.organizations_ext.models import (
    Organization,
    OrganizationOwner,
    OrganizationUser,
)
from apps.users.models import User


def groups_hash(groups: list[str]) -> str:
    """Stable short hash so cache keys reflect actual group membership."""
    payload = "|".join(sorted(groups)).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


async def get_or_create_user(email: str, name: str) -> User:
    """Return a local user for ``email``, JIT-creating it when missing.

    Email lookup uses the column's case-insensitive collation, so
    ``Foo@Example.com`` and ``foo@example.com`` resolve to the same row.
    """
    user, created = await User.objects.aget_or_create(email=email)
    changed = created
    if created:
        # Authentik owns authentication; the local account must never
        # be loggable via a password (and allauth should not offer
        # password-change UI for it).
        user.set_unusable_password()
        user.is_active = True
        changed = True
    elif not user.is_active:
        user.is_active = True
        changed = True
    name = (name or "").strip()
    if name and (created or not user.name):
        user.name = name
        changed = True
    if changed:
        await user.asave()

    # Ensure allauth sees a verified primary email; Authentik already
    # verified ownership upstream, so we never want a SPA "verify your
    # email" prompt to show up for these users.
    #
    # allauth's EmailAddress has a partial UNIQUE constraint on
    # (user, primary) WHERE primary=True, so at most one row per user
    # may be primary. If the user already has a different primary row
    # (e.g. a password-signup email from before Authentik took over)
    # we MUST demote it BEFORE inserting/setting primary=True on the
    # Authentik row — otherwise the constraint trips and the JIT
    # provision raises IntegrityError on the request path. Secondary
    # (non-primary) rows are left untouched.
    await (
        EmailAddress.objects.filter(user=user, primary=True)
        .exclude(email=email)
        .aupdate(primary=False)
    )
    existing = await EmailAddress.objects.filter(user=user, email=email).afirst()
    if existing is None:
        await EmailAddress.objects.acreate(
            user=user, email=email, verified=True, primary=True
        )
    else:
        update_fields: list[str] = []
        if not existing.verified:
            existing.verified = True
            update_fields.append("verified")
        if not existing.primary:
            existing.primary = True
            update_fields.append("primary")
        if update_fields:
            await existing.asave(update_fields=update_fields)
    return user


async def sync_org_memberships(
    user: User, role: OrganizationUserRole, groups_hash: str
) -> None:
    """Apply ``role`` to ``user``'s membership of every non-deleted org.

    Skip when we've already synced this exact group set. Ownerless
    orgs are avoided: the very first member of an org becomes OWNER
    regardless of the resolved role, and an existing primary
    ``OrganizationOwner`` is never demoted below OWNER.
    """
    cache_key = f"authentik_roles:{user.id}:{groups_hash}"
    if await cache.aget(cache_key):
        return

    async for org in Organization.objects.filter(is_deleted=False).aiterator():
        org_user = await OrganizationUser.objects.filter(
            organization=org, user=user
        ).afirst()

        if org_user is None:
            # Ownerless guard on creation: an empty org gets the new
            # user as OWNER, otherwise their resolved role.
            org_has_members = await OrganizationUser.objects.filter(
                organization=org
            ).aexists()
            assigned_role = OrganizationUserRole.OWNER if not org_has_members else role
            await OrganizationUser.objects.acreate(
                organization=org, user=user, role=assigned_role
            )
            continue

        if org_user.role == role:
            continue

        # Ownerless guard on update: never demote the primary
        # OrganizationOwner below OWNER, mirroring
        # update_organization_member in organizations_ext.api.
        is_primary_owner = await OrganizationOwner.objects.filter(
            organization_user=org_user
        ).aexists()
        if is_primary_owner and role < OrganizationUserRole.OWNER:
            continue

        org_user.role = role
        await org_user.asave(update_fields=["role"])

    await cache.aset(cache_key, True, settings.AUTHENTIK_ROLE_SYNC_CACHE_TTL)
