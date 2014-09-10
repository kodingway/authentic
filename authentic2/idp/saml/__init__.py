from django.utils.translation import ugettext_lazy as _

__version__ = '1.0.0'

class Plugin(object):
    def get_before_urls(self):
        from . import app_settings
        from django.conf.urls import patterns, include
        from authentic2.decorators import setting_enabled, required

        return required(
                setting_enabled('ENABLE', settings=app_settings),
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
