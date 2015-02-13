from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ImproperlyConfigured

try:
    import openid
except ImportError:
    from . import app_settings
    if app_settings.ENABLE:
        raise ImproperlyConfigured('OpenID idp is enabled by python-openid is not installed')
    class Plugin(object):
        pass
else:
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
                        (r'^idp/openid/', include(__name__ + '.urls'))))

        def get_apps(self):
            return [__name__]

        def get_admin_modules(self):
            from admin_tools.dashboard import modules
            return [modules.ModelList(
                _('OpenID'),
                models=(
                    '%s.models.*' % __name__,
                ),
            )]

        def get_idp_backends(self):
            return ['%s.backend.OpenIDBackend' % __name__]

        def get_before_middleware(self):
            return ['%s.middleware.OpenIDMiddleware' % __name__]
