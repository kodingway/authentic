from django.utils.translation import ugettext_lazy as _

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
                patterns('',
                    (r'^idp/saml2/', include(__name__ + '.urls'))))

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


from django.apps import AppConfig
class SAML2IdPConfig(AppConfig):
    name = 'authentic2.idp.saml'
    label = 'authentic2_idp_saml'
default_app_config = 'authentic2.idp.saml.SAML2IdPConfig'

