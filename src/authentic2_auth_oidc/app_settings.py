class AppSettings(object):
    '''Thanks django-allauth'''
    __SENTINEL = object()

    def __init__(self, prefix):
        self.prefix = prefix

    def _setting(self, name, dflt=__SENTINEL):
        from django.conf import settings
        from django.core.exceptions import ImproperlyConfigured

        v = getattr(settings, self.prefix + name, dflt)
        if v is self.__SENTINEL:
            raise ImproperlyConfigured('Missing setting %r' % (self.prefix + name))
        return v

    @property
    def ENABLE(self):
        return self._setting('ENABLE', True)


import sys

app_settings = AppSettings('A2_AUTH_OIDC_')
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
