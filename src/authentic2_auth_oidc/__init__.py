from django.utils.translation import ugettext_lazy as _


class Plugin(object):
    def get_before_urls(self):
        from . import urls
        return urls.urlpatterns

    def get_apps(self):
        return [__name__]

    def get_authentication_backends(self):
        return ['authentic2_auth_oidc.backends.OIDCBackend']

    def get_auth_frontends(self):
        return ['authentic2_auth_oidc.auth_frontends.OIDCFrontend']

    def redirect_logout_list(self, request, next=None):
        return []

    def get_admin_modules(self):
        from admin_tools.dashboard import modules
        return [modules.ModelList(
            _('OpenID Connect authentication'),
            models=(
                'authentic2_auth_oidc.models.OIDCProvider',
                'authentic2_auth_oidc.models.OIDCAccount',
            ),
        )]
