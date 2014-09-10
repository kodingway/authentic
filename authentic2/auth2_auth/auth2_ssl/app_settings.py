# -*- coding: utf-8 -*-

import sys


class AppSettings(object):
    '''Thanks django-allauth'''
    __DEFAULTS = dict(
            # settings for TEST only, make it easy to simulate the SSL
            # environment
            ENABLE=False,
            FORCE_ENV={},
            ACCEPT_SELF_SIGNED=False,
            STRICT_MATCH=False,
            SUBJECT_MATCH_KEYS=('subject_dn', 'issuer_dn'),
            CREATE_USERNAME_CALLBACK=None,
            USE_COOKIE=False,
            CREATE_USER=False,
    )

    def __init__(self, prefix):
        self.prefix = prefix

    def _setting(self, name, dflt):
        from django.conf import settings
        return getattr(settings, self.prefix+name, dflt)

    def __getattr__(self, name):
        if name not in self.__DEFAULTS:
            raise AttributeError(name)
        return self._setting(name, self.__DEFAULTS[name])


app_settings = AppSettings('SSLAUTH_')
app_settings.__name__ = __name__
app_settings.__file__ = __file__
sys.modules[__name__] = app_settings
