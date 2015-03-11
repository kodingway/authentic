import sys

class AppSettings(object):
    __PREFIX = 'A2_MANAGER_'
    __DEFAULTS = {
            'HOMEPAGE_URL': None,
            'HOMEPAGE_TITLE': None,
            'LOGOUT_URL': None,
    }

    @property
    def HOMEPAGE_URL(self):
        from django.conf import settings
        return getattr(settings,
                '%sHOMEPAGE_URL' % self.__PREFIX,
                getattr(settings, 
                    'MANAGER_HOMEPAGE_URL',
                    self.__DEFAULTS['HOMEPAGE_URL']))

    @property
    def HOMEPAGE_TITLE(self):
        from django.conf import settings
        return getattr(settings,
                '%sHOMEPAGE_TITLE' % self.__PREFIX,
                getattr(settings, 
                    'MANAGER_HOMEPAGE_TITLE',
                    self.__DEFAULTS['HOMEPAGE_URL']))

    def __getattr__(self, name):
        from django.conf import settings
        if name not in self.__DEFAULTS:
            raise AttributeError
        return getattr(settings, self.__PREFIX + name, self.__DEFAULTS[name])

app_settings = AppSettings()
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
