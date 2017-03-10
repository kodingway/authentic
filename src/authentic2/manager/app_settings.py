import sys


class AppSettings(object):
    __PREFIX = 'A2_MANAGER_'
    __DEFAULTS = {
        'HOMEPAGE_URL': None,
        'ROLE_FORM_CLASS': None,
        'ROLES_SHOW_PERMISSIONS': False,
        'ROLE_MEMBERS_FROM_OU': False,
    }

    def __getattr__(self, name):
        from django.conf import settings
        if name not in self.__DEFAULTS:
            raise AttributeError
        return getattr(settings, self.__PREFIX + name, self.__DEFAULTS[name])

app_settings = AppSettings()
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
