import sys

from django.conf import settings

class AppSettings(object):
    __PREFIX = 'SAML_'
    __NO_DEFAULT = object()
    __DEFAULTS = {
    }

    def __settings(self, name):
        full_name = self._PREFIX + name
        if name not in __DEFAULT:
            raise AttributeError('unknown settings '+full_name)
        try:
            default = self.__DEFAULTS[name]
            if default is self._NO_DEFAULT:
                return getattr(settings, full_name)
            return getattr(settings, full_name, default)
        except AttributeError:
            raise ImproperlyConfigured('missing settings '+full_name)

    def __getattr__(self, name):
        return self.__settings(name)

app_settings = AppSettings()
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
