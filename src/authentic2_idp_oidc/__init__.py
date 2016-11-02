from django.utils.translation import ugettext_lazy as _


class Plugin(object):
    def get_before_urls(self):
        from . import urls
        return urls.urlpatterns

    def get_apps(self):
        return [__name__]

    def redirect_logout_list(self, request, next=None):
        return []

    def get_admin_modules(self):
        from admin_tools.dashboard import modules
        return [modules.ModelList(
            _('OpenID Connect authentication'),
            models=(
                'authentic2_idp_oidc.models.*',
            ),
        )]
