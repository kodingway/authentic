class Plugin(object):
    def get_before_urls(self):
        from . import urls
        return urls.urlpatterns

    def get_apps(self):
        return ['mellon', __name__]

    def get_authentication_backends(self):
        return ['authentic2_auth_saml.backends.SAMLBackend']

    def get_auth_frontends(self):
        return ['authentic2_auth_saml.auth_frontends.SAMLFrontend']

    def redirect_logout_list(self, request, next_url=None):
        from mellon.views import logout
        if 'mellon_session' in request.session:
            response = logout(request)
            return [response['Location']]
        return []
