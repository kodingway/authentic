from django.utils.translation import ugettext_lazy as _
from django.core.urlresolvers import reverse

from authentic2.utils import make_url


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
        from .models import OIDCProvider

        tokens = request.session.get('auth_oidc', {}).get('tokens', [])
        urls = []
        if tokens:
            for token in tokens:
                provider = OIDCProvider.objects.get(pk=token['provider_pk'])
                # ignore providers wihtout SLO
                if not provider.end_session_endpoint:
                    continue
                params = {}
                if 'id_token' in token['token_response']:
                    params['id_token_hint'] = token['token_response']['id_token']
                params['post_logout_redirect_uri'] = request.build_absolute_uri(reverse('auth_logout'))
                urls.append(make_url(provider.end_session_endpoint, params=params))
        return urls

    def get_admin_modules(self):
        from admin_tools.dashboard import modules
        return [modules.ModelList(
            _('OpenID Connect authentication'),
            models=(
                'authentic2_auth_oidc.models.OIDCProvider',
                'authentic2_auth_oidc.models.OIDCAccount',
            ),
        )]
