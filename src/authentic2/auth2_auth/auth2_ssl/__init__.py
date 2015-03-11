class Plugin(object):
    def get_before_urls(self):
        from . import app_settings
        from django.conf.urls import patterns, include
        from authentic2.decorators import setting_enabled, required

        return required(
                setting_enabled('ENABLE', settings=app_settings),
                patterns('',
                    (r'^accounts/sslauth/', include(__name__ + '.urls'))))

    def get_apps(self):
        return [__name__]

    def get_authentication_backends(self):
        return ['authentic2.auth2_auth.auth2_ssl.backends.SSLBackend']

    def get_auth_frontends(self):
        return ['authentic2.auth2_auth.auth2_ssl.frontends.SSLFrontend']
