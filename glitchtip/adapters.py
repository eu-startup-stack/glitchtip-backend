from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.internal.flows.login import record_authentication
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings

from apps.users.utils import (
    is_social_apps_user_registration_open,
    is_user_registration_open,
)
from glitchtip.email import GlitchTipEmail


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def is_open_for_signup(self, request, _sociallogin):
        # Behind Authentik, account creation is JIT from the proxy
        # headers -- the allauth signup flow must be closed off or it
        # becomes a way to register without an Authentik-issued role.
        if settings.AUTHENTIK_PROXY_AUTH_ENABLED:
            return False
        return is_social_apps_user_registration_open()


class CustomDefaultAccountAdapter(DefaultAccountAdapter):
    def send_mail(self, template_prefix, email, context):
        # Single chokepoint for all allauth mail (email confirmation, password
        # reset, MFA notices). When email is disabled, skip without rendering or
        # sending -- callers like the password-reset endpoint still return their
        # normal response, they just don't deliver mail.
        if not settings.EMAIL_ENABLED:
            return
        return super().send_mail(template_prefix, email, context)

    def render_mail(self, template_prefix, email, context, headers=None):
        headers = headers or {}
        default_headers = GlitchTipEmail.get_default_headers()
        for key, value in default_headers.items():
            if key not in headers:
                headers[key] = value
        return super().render_mail(template_prefix, email, context, headers)

    def is_open_for_signup(self, request):
        # Behind Authentik, account creation is JIT from the proxy
        # headers -- the allauth signup flow must be closed off or it
        # becomes a way to register without an Authentik-issued role.
        if settings.AUTHENTIK_PROXY_AUTH_ENABLED:
            return False
        return is_user_registration_open()

    def save_user(self, request, user, form, commit=True):
        # Consider a signup a form of authentication
        user = super().save_user(request, user, form, commit)
        if commit:
            record_authentication(request, user, method="signup")
        return user
