class AppSettings(object):
    __DEFAULTS = dict(
        MANAGED_CONTENT_TYPES=None,
    )

    def __init__(self, prefix):
        self.prefix = prefix

    def _setting(self, name, dflt):
        from django.conf import settings
        return getattr(settings, name, dflt)

    def _setting_with_prefix(self, name, dflt):
        return self._setting(self.prefix + name, dflt)

    def __getattr__(self, name):
        if name not in self.__DEFAULTS:
            raise AttributeError(name)
        return self._setting_with_prefix(name, self.__DEFAULTS[name])


# Ugly? Guido recommends this himself ...
# http://mail.python.org/pipermail/python-ideas/2012-May/014969.html
import sys
app_settings = AppSettings('A2_RBAC_')
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
