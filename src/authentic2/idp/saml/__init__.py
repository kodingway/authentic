import django
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.core.checks import register, Warning, Tags
from django.apps import AppConfig


class Plugin(object):
    def get_before_urls(self):
        from . import app_settings
        from django.conf.urls import patterns, include
        from authentic2.decorators import (setting_enabled, required,
                                           lasso_required)

        return required(
            (
                setting_enabled('ENABLE', settings=app_settings),
                lasso_required()
            ),
            patterns('', (r'^idp/saml2/', include(__name__ + '.urls'))))

    def get_apps(self):
        return ['authentic2.idp.saml']

    def get_admin_modules(self):
        from admin_tools.dashboard import modules
        return [modules.ModelList(
            _('SAML2'),
            models=(
                'authentic2.saml.models.LibertyProvider',
                'authentic2.saml.models.SPOptionsIdPPolicy',
                'authentic2.saml.models.IdPOptionsSPPolicy',
            ),
        )]

    def get_idp_backends(self):
        return ['authentic2.idp.saml.backend.SamlBackend']

    def check_origin(self, request, origin):
        from authentic2.cors import make_origin
        from authentic2.saml.models import LibertySession
        for session in LibertySession.objects.filter(
                django_session_key=request.session.session_key):
            provider_origin = make_origin(session.provider_id)
            if origin == provider_origin:
                return True


class SAML2IdPConfig(AppConfig):
    name = 'authentic2.idp.saml'
    label = 'authentic2_idp_saml'
default_app_config = 'authentic2.idp.saml.SAML2IdPConfig'


def check_authentic2_config(app_configs, **kwargs):
    from . import app_settings
    errors = []

    if not settings.DEBUG and app_settings.ENABLE and \
        (app_settings.is_default('SIGNATURE_PUBLIC_KEY') or
         app_settings.is_default('SIGNATURE_PRIVATE_KEY')):
        errors.append(
            Warning(
                'You should not use default SAML keys in production',
                hint='Generate new RSA keys and change the value of '
                     'A2_IDP_SAML2_SIGNATURE_PUBLIC_KEY and '
                     'A2_IDP_SAML2_SIGNATURE_PRIVATE_KEY in your setting file',
            )
        )
    return errors

if django.VERSION >= (1, 8):
    check_authentic2_config = register(Tags.security,
                                       deploy=True)(check_authentic2_config)
else:
    check_authentic2_config = register()(check_authentic2_config)
