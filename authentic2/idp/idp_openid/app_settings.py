class AppSettings(object):
    __DEFAULTS = dict(
            ENABLE=False,
            OPENID_ACTIONS={},
    )

    def __init__(self, prefix):
        self.prefix = prefix

    def _setting(self, name, dflt):
        from django.conf import settings
        return getattr(settings, self.prefix+name, dflt)

    @property
    def ENABLE(self):
        return self._setting('%sENABLE' % self.prefix,
                self._settings('IDP_OPENID',
                    self.__DEFAULTS['ENABLE']))

    def __getattr__(self, name):
        if name not in self.__DEFAULTS:
            raise AttributeError(name)
        return self._setting(name, self.__DEFAULTS[name])


# Ugly? Guido recommends this himself ...
# http://mail.python.org/pipermail/python-ideas/2012-May/014969.html
import sys
app_settings = AppSettings('A2_IDP_OPENID_')
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
