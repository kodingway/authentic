import sys

from django.conf import settings
from django.utils.translation import ugettext_lazy as _

class AppSettings(object):
    __PREFIX = 'SAML_'
    __NAMES = ('ALLOWED_FEDERATION_MODE', 'DEFAULT_FEDERATION_MODE')

    class FEDERATION_MODE:
        EXPLICIT = 0
        IMPLICIT = 1

        choices = ((EXPLICIT, _('explicit')),
                   (IMPLICIT, _('implicit')))

        @classmethod
        def get_choices(cls, app_settings):
            l = []
            for choice in cls.choices:
                if choice[0] in app_settings.ALLOWED_FEDERATION_MODE:
                    l.append(choice)
            return l

        @classmethod
        def get_default(cls, app_settings):
            return app_settings.DEFAULT_FEDERATION_MODE

    __DEFAULTS = {
            'ALLOWED_FEDERATION_MODE': (FEDERATION_MODE.EXPLICIT,
                FEDERATION_MODE.IMPLICIT),
            'DEFAULT_FEDERATION_MODE': FEDERATION_MODE.EXPLICIT,
    }


    def __settings(self, name):
        full_name = self.__PREFIX + name
        if name not in self.__NAMES:
            raise AttributeError('unknown settings '+full_name)
        try:
            if name in self.__DEFAULTS:
                return getattr(settings, full_name, self.__DEFAULTS[name])
            else:
                return getattr(settings, full_name)
        except AttributeError:
            raise ImproperlyConfigured('missing settings '+full_name)

    def __getattr__(self, name):
        return self.__settings(name)

app_settings = AppSettings()
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
