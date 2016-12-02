import logging

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
                if 'access_token' in token['token_response'] and provider.token_revocation_endpoint:
                    self.revoke_token(provider, token['token_response']['access_token'])
                params['post_logout_redirect_uri'] = request.build_absolute_uri(reverse('auth_logout'))
                urls.append(make_url(provider.end_session_endpoint, params=params))
        return urls

    def revoke_token(self, provider, access_token):
        import requests

        logger = logging.getLogger(__name__)

        url = provider.token_revocation_endpoint
        try:
            response = requests.post(url, auth=(provider.client_id, provider.client_secret),
                                     data={'token': access_token, 'token_type': 'access_token'},
                                     timeout=10)
        except requests.RequestException as e:
            logger.warning(u'failed to revoke access token from OIDC provider %s: %s',
                           provider.issuer, e)
            return
        try:
            response.raise_for_status()
        except requests.RequestException as e:
            try:
                content = response.json()
            except ValueError:
                content = None
            logger.warning(u'failed to revoke access token from OIDC provider %s: %s, %s',
                           provider.issuer, e, content)
            return
        logger.debug(u'revoked token from OIDC provider %s', provider.issuer)

    def get_admin_modules(self):
        from admin_tools.dashboard import modules
        return [modules.ModelList(
            _('OpenID Connect authentication'),
            models=(
                'authentic2_auth_oidc.models.OIDCProvider',
                'authentic2_auth_oidc.models.OIDCAccount',
            ),
        )]
